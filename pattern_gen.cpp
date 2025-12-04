#include "pattern_gen.h"
#include "debug_dump.h"
#include <QCryptographicHash>
#include <algorithm>
#include <cstring>

// Check if debug mode is enabled - checked every time (no caching)
// Set LUMINA_DEBUG=1 to enable
static bool isDebugEnabled() {
    const char* env = std::getenv("LUMINA_DEBUG");
    return (env && *env == '1');
}

namespace lumina {

// ============================================================================
// X86MaskGenerator Implementation
// ============================================================================

X86MaskGenerator::X86MaskGenerator(bool is64bit)
    : m_is64bit(is64bit), m_funcStart(0), m_funcEnd(0), m_capstone(0), m_capstoneReady(false) {}

X86MaskGenerator::~X86MaskGenerator() {
    if (m_capstoneReady) {
        cs_close(&m_capstone);
    }
}

bool X86MaskGenerator::initCapstone() {
    if (m_capstoneReady) {
        return true;
    }

    cs_mode mode = m_is64bit ? CS_MODE_64 : CS_MODE_32;
    if (cs_open(CS_ARCH_X86, mode, &m_capstone) != CS_ERR_OK) {
        return false;
    }

    cs_option(m_capstone, CS_OPT_DETAIL, CS_OPT_ON);
    m_capstoneReady = true;
    return true;
}

// Check if an address is a valid external reference (should be masked)
// This matches IDA's Lumina behavior:
// - Must be > 0x1000 (not in header/null page)
// - Must be < reasonable limit (to filter float constants like 0x3f800000)
// - Must be outside the function range (external reference)
static bool isValidExternalRef(
    BinaryNinja::BinaryView* bv,
    uint64_t target,
    uint64_t funcStart,
    uint64_t funcEnd,
    uint64_t imageStart,
    uint64_t imageEnd)
{
    // Not in null page / header
    uint64_t minAddr = imageStart ? imageStart : 0x1000;
    if (target < minAddr) return false;

    // Require the address to live in a mapped segment; avoids masking plain constants.
    if (bv) {
        auto seg = bv->GetSegmentAt(target);
        if (!seg) {
            return false;
        }
    }

    // Use image end if available, otherwise use heuristic
    uint64_t maxAddr = imageEnd > 0 ? imageEnd : 0x100000;
    if (target > maxAddr) return false;  // Probably not an address (e.g., float constant)

    // Must be outside function range (external reference)
    if (target >= funcStart && target < funcEnd) return false;  // Internal reference

    return true;  // External reference, should be masked
}

InstructionMask X86MaskGenerator::getMask(
    BinaryNinja::BinaryView* bv,
    uint64_t addr,
    const std::vector<uint8_t>& raw_bytes)
{
    InstructionMask result;
    result.raw_bytes = raw_bytes;
    result.mask.resize(raw_bytes.size(), 0);  // Default: keep all bytes

    if (raw_bytes.empty()) {
        return result;
    }

    // Get function context for valid_loc check
    uint64_t funcStart = m_funcStart;
    uint64_t funcEnd = m_funcEnd;
    uint64_t imageEnd = bv ? bv->GetEnd() : 0;
    uint64_t imageStart = bv ? bv->GetStart() : 0;

    if (!initCapstone()) {
        return result;
    }

    cs_insn* insn = nullptr;
    size_t count = cs_disasm(m_capstone, raw_bytes.data(), raw_bytes.size(), addr, 1, &insn);
    if (count == 0 || !insn || !insn[0].detail) {
        if (insn) {
            cs_free(insn, count);
        }
        return result;
    }

    const cs_x86& x86 = insn[0].detail->x86;
    const cs_x86_encoding& enc = insn[0].detail->x86.encoding;
    auto validRef = [&](uint64_t target) {
        return isValidExternalRef(bv, target, funcStart, funcEnd, imageStart, imageEnd);
    };
    auto addMask = [&](size_t offset, size_t length) {
        for (size_t i = 0; i < length && offset + i < result.mask.size(); i++) {
            result.mask[offset + i] = 0xFF;
        }
    };

    // Query relocation once per instruction for immediate masking heuristics
    bool hasReloc = bv && !bv->GetRelocationsAt(addr).empty();

    // Mask displacement for RIP-relative references to external addresses and FS/GS segments
    bool maskDisp = false;
    for (size_t i = 0; i < x86.op_count; i++) {
        const cs_x86_op& op = x86.operands[i];
        if (op.type != X86_OP_MEM) {
            continue;
        }

        if (op.mem.segment == X86_REG_FS || op.mem.segment == X86_REG_GS) {
            maskDisp = true;
            break;
        }

        if (op.mem.base == X86_REG_RIP) {
            uint64_t target = static_cast<uint64_t>(op.mem.disp + insn[0].address + insn[0].size);
            if (validRef(target)) {
                maskDisp = true;
                break;
            }
        }
    }

    if (maskDisp && enc.disp_offset && enc.disp_size) {
        size_t dispSize = enc.disp_size;
        if (enc.imm_offset && enc.imm_offset > enc.disp_offset) {
            dispSize = enc.imm_offset - enc.disp_offset;
        }
        addMask(enc.disp_offset, dispSize);
    }

    // Mask immediates that look like external addresses
    bool isBranchOrCall = cs_insn_group(m_capstone, &insn[0], CS_GRP_JUMP) ||
                          cs_insn_group(m_capstone, &insn[0], CS_GRP_CALL);
    if (!isBranchOrCall) {
        // Fallback based on mnemonic to cover cases where Capstone groups are missing
        std::string mnem = insn[0].mnemonic ? insn[0].mnemonic : "";
        if (!mnem.empty() && (mnem[0] == 'j' || mnem == "call")) {
            isBranchOrCall = true;
        }
    }

    // Special-case CALL: mask if it targets an external address
    bool isCall = cs_insn_group(m_capstone, &insn[0], CS_GRP_CALL);
    if (!isCall) {
        std::string mnem = insn[0].mnemonic ? insn[0].mnemonic : "";
        if (mnem == "call") {
            isCall = true;
        }
    }

    if (isCall && enc.imm_offset && enc.imm_size) {
        for (size_t i = 0; i < x86.op_count; i++) {
            const cs_x86_op& op = x86.operands[i];
            if (op.type == X86_OP_IMM) {
                uint64_t target = static_cast<uint64_t>(op.imm);
                auto seg = bv ? bv->GetSegmentAt(target) : nullptr;
                bool isExec = seg && ((seg->GetFlags() & SegmentExecutable) != 0);
                if (validRef(target) && (isExec || hasReloc)) {
                    addMask(enc.imm_offset, enc.imm_size);
                }
                break;
            }
        }
    }

    // Mask other immediates that look like external addresses (never for jumps)
    bool maskImm = false;
    for (size_t i = 0; i < x86.op_count; i++) {
        const cs_x86_op& op = x86.operands[i];
        if (op.type == X86_OP_IMM) {
            if (isBranchOrCall) {
                continue;  // Do not mask branch/jump displacements
            }
            uint64_t immVal = static_cast<uint64_t>(op.imm);
            auto seg = bv ? bv->GetSegmentAt(immVal) : nullptr;
            bool isExec = seg && ((seg->GetFlags() & SegmentExecutable) != 0);
            if (validRef(immVal) && (hasReloc || isExec)) {
                maskImm = true;
                break;
            }
        }
    }

    if (maskImm && enc.imm_offset && enc.imm_size) {
        addMask(enc.imm_offset, enc.imm_size);
    }

    cs_free(insn, count);
    return result;
}

// ============================================================================
// ARM32 Mask Generator Implementation
// ============================================================================

namespace arm {

// ARM32 instruction classes (for non-Thumb)
enum ARMOpClass {
    ARM_OP_NORMAL,
    ARM_OP_BRANCH,      // B, BL (24-bit offset)
    ARM_OP_LDR_PC,      // LDR with PC-relative addressing
    ARM_OP_ADR,         // ADR pseudo-instruction
};

// Check if ARM instruction is a branch (B/BL)
inline bool isBranch(uint32_t insn) {
    uint8_t cond_op = (insn >> 24) & 0xFF;
    return (cond_op & 0x0E) == 0x0A;  // 1x1x = B/BL
}

// Check if ARM instruction is LDR/STR with PC base
inline bool isLdrPCRelative(uint32_t insn) {
    // LDR Rd, [PC, #offset] has pattern: cond 01 I P U 0 W 1 1111 Rd offset
    // Bits [27:26] = 01, [15:12] = Rd, [19:16] = Rn = 1111 (PC)
    if ((insn & 0x0C000000) != 0x04000000) return false;  // Not load/store
    uint8_t rn = (insn >> 16) & 0xF;
    return rn == 15;  // PC-relative
}

} // namespace arm

InstructionMask ARMMaskGenerator::getMask(
    BinaryNinja::BinaryView* bv,
    uint64_t addr,
    const std::vector<uint8_t>& raw_bytes)
{
    InstructionMask result;
    result.raw_bytes = raw_bytes;
    result.mask.resize(raw_bytes.size(), 0);

    if (m_isThumb) {
        // Thumb mode: 2 or 4 byte instructions
        if (raw_bytes.size() >= 2) {
            uint16_t insn = raw_bytes[0] | (raw_bytes[1] << 8);

            // Check for BL/BLX (32-bit Thumb instruction)
            if (raw_bytes.size() >= 4) {
                uint16_t hw1 = raw_bytes[0] | (raw_bytes[1] << 8);
                uint16_t hw2 = raw_bytes[2] | (raw_bytes[3] << 8);

                // BL: 11110 S imm10 | 11 J1 1 J2 imm11
                if ((hw1 & 0xF800) == 0xF000 && (hw2 & 0xD000) == 0xD000) {
                    // Mask the offset bits in both halfwords
                    // Lower 11 bits of hw1 and lower 11 bits of hw2
                    result.mask[0] = 0xFF;
                    result.mask[1] = 0x07;  // Mask bits [10:0] of hw1
                    result.mask[2] = 0xFF;
                    result.mask[3] = 0x07;  // Mask bits [10:0] of hw2
                }
            }

            // Check for conditional branches (16-bit)
            // B<cond>: 1101 cond imm8
            if ((insn & 0xF000) == 0xD000 && (insn & 0x0F00) != 0x0E00 && (insn & 0x0F00) != 0x0F00) {
                result.mask[0] = 0xFF;  // Mask the 8-bit offset
            }

            // Unconditional branch: 11100 imm11
            if ((insn & 0xF800) == 0xE000) {
                result.mask[0] = 0xFF;
                result.mask[1] = 0x07;  // Mask 11-bit offset
            }

            // LDR (literal) - PC-relative load
            // Pattern: 01001 Rt imm8
            if ((insn & 0xF800) == 0x4800) {
                result.mask[0] = 0xFF;  // Mask the 8-bit offset
            }
        }
    } else {
        // ARM32 mode: 4 byte instructions
        if (raw_bytes.size() >= 4) {
            uint32_t insn = raw_bytes[0] | (raw_bytes[1] << 8) |
                           (raw_bytes[2] << 16) | (raw_bytes[3] << 24);

            // B/BL: cond 101 L offset24
            if (arm::isBranch(insn)) {
                // Mask the 24-bit offset (bits [23:0])
                result.mask[0] = 0xFF;
                result.mask[1] = 0xFF;
                result.mask[2] = 0xFF;
                // Keep condition code and opcode in byte 3
            }

            // LDR PC-relative
            if (arm::isLdrPCRelative(insn)) {
                // Mask the 12-bit offset (bits [11:0])
                result.mask[0] = 0xFF;
                result.mask[1] = 0x0F;  // Lower 4 bits of byte 1
            }
        }
    }

    return result;
}

// ============================================================================
// ARM64 Mask Generator Implementation
// ============================================================================

namespace arm64 {

// Check if instruction is B/BL (unconditional branch)
inline bool isBranch(uint32_t insn) {
    // B: 000101 imm26
    // BL: 100101 imm26
    return (insn & 0x7C000000) == 0x14000000;
}

// Check if instruction is B.cond (conditional branch)
inline bool isBranchCond(uint32_t insn) {
    // B.cond: 01010100 imm19 0 cond
    return (insn & 0xFF000010) == 0x54000000;
}

// Check if instruction is CBZ/CBNZ
inline bool isCBZ(uint32_t insn) {
    // CBZ/CBNZ: sf 011010 op imm19 Rt
    return (insn & 0x7E000000) == 0x34000000;
}

// Check if instruction is TBZ/TBNZ
inline bool isTBZ(uint32_t insn) {
    // TBZ/TBNZ: b5 011011 op b40 imm14 Rt
    return (insn & 0x7E000000) == 0x36000000;
}

// Check if instruction is ADRP
inline bool isADRP(uint32_t insn) {
    // ADRP: 1 immlo 10000 immhi Rd
    return (insn & 0x9F000000) == 0x90000000;
}

// Check if instruction is ADR
inline bool isADR(uint32_t insn) {
    // ADR: 0 immlo 10000 immhi Rd
    return (insn & 0x9F000000) == 0x10000000;
}

// Check if instruction is LDR (literal)
inline bool isLDRLiteral(uint32_t insn) {
    // LDR (literal): opc 011 V 00 imm19 Rt
    return (insn & 0x3B000000) == 0x18000000;
}

} // namespace arm64

InstructionMask ARM64MaskGenerator::getMask(
    BinaryNinja::BinaryView* bv,
    uint64_t addr,
    const std::vector<uint8_t>& raw_bytes)
{
    InstructionMask result;
    result.raw_bytes = raw_bytes;
    result.mask.resize(raw_bytes.size(), 0);

    if (raw_bytes.size() < 4) return result;

    // ARM64 instructions are always 4 bytes, little-endian
    uint32_t insn = raw_bytes[0] | (raw_bytes[1] << 8) |
                   (raw_bytes[2] << 16) | (raw_bytes[3] << 24);

    // B/BL: mask 26-bit offset (bits [25:0])
    if (arm64::isBranch(insn)) {
        result.mask[0] = 0xFF;
        result.mask[1] = 0xFF;
        result.mask[2] = 0xFF;
        result.mask[3] = 0x03;  // bits [25:24]
    }

    // B.cond: mask 19-bit offset (bits [23:5])
    if (arm64::isBranchCond(insn)) {
        result.mask[0] = 0xE0;  // bits [7:5]
        result.mask[1] = 0xFF;
        result.mask[2] = 0xFF;
        result.mask[3] = 0x00;
    }

    // CBZ/CBNZ: mask 19-bit offset (bits [23:5])
    if (arm64::isCBZ(insn)) {
        result.mask[0] = 0xE0;
        result.mask[1] = 0xFF;
        result.mask[2] = 0xFF;
        result.mask[3] = 0x00;
    }

    // TBZ/TBNZ: mask 14-bit offset (bits [18:5])
    if (arm64::isTBZ(insn)) {
        result.mask[0] = 0xE0;
        result.mask[1] = 0xFF;
        result.mask[2] = 0x07;
        result.mask[3] = 0x00;
    }

    // ADRP: mask 21-bit page offset (bits [30:29] + bits [23:5])
    if (arm64::isADRP(insn)) {
        result.mask[0] = 0xE0;  // bits [7:5]
        result.mask[1] = 0xFF;
        result.mask[2] = 0xFF;
        result.mask[3] = 0x60;  // bits [30:29]
    }

    // ADR: mask 21-bit offset (bits [30:29] + bits [23:5])
    if (arm64::isADR(insn)) {
        result.mask[0] = 0xE0;
        result.mask[1] = 0xFF;
        result.mask[2] = 0xFF;
        result.mask[3] = 0x60;
    }

    // LDR (literal): mask 19-bit offset (bits [23:5])
    if (arm64::isLDRLiteral(insn)) {
        result.mask[0] = 0xE0;
        result.mask[1] = 0xFF;
        result.mask[2] = 0xFF;
        result.mask[3] = 0x00;
    }

    return result;
}

// ============================================================================
// Generic Mask Generator Implementation
// ============================================================================

InstructionMask GenericMaskGenerator::getMask(
    BinaryNinja::BinaryView* bv,
    uint64_t addr,
    const std::vector<uint8_t>& raw_bytes)
{
    InstructionMask result;
    result.raw_bytes = raw_bytes;
    result.mask.resize(raw_bytes.size(), 0);

    if (!m_arch || raw_bytes.empty()) return result;

    // Use Binary Ninja's instruction info to detect branches
    BinaryNinja::InstructionInfo info;
    if (!m_arch->GetInstructionInfo(raw_bytes.data(), addr, raw_bytes.size(), info)) {
        return result;
    }

    // If instruction has branch targets, try to mask the operand bytes
    // This is a heuristic - we assume the target address is encoded in the
    // latter part of the instruction
    for (size_t i = 0; i < info.branchCount; i++) {
        if (info.branchType[i] == CallDestination ||
            info.branchType[i] == UnconditionalBranch ||
            info.branchType[i] == TrueBranch ||
            info.branchType[i] == FalseBranch) {

            // Heuristic: mask the last 4 bytes (common for 32-bit offsets)
            // or last 1 byte for short branches
            size_t insnLen = info.length;
            if (insnLen > 1) {
                // Conservative: mask everything except the first byte (opcode)
                for (size_t j = 1; j < raw_bytes.size(); j++) {
                    result.mask[j] = 0xFF;
                }
            }
            break;
        }
    }

    return result;
}

std::string GenericMaskGenerator::getName() const {
    return m_arch ? m_arch->GetName() : "unknown";
}

// ============================================================================
// Pattern Generator Implementation
// ============================================================================

PatternGenerator::PatternGenerator(BinaryViewRef bv)
    : m_bv(bv)
{
    m_maskGen = createMaskGenerator();
}

PatternGenerator::~PatternGenerator() = default;

std::unique_ptr<ArchMaskGenerator> PatternGenerator::createMaskGenerator() {
    if (!m_bv) {
        return std::make_unique<GenericMaskGenerator>(nullptr);
    }

    auto arch = m_bv->GetDefaultArchitecture();
    if (!arch) {
        return std::make_unique<GenericMaskGenerator>(nullptr);
    }

    std::string archName = arch->GetName();

    // x86/x64
    if (archName == "x86" || archName == "x86_32") {
        return std::make_unique<X86MaskGenerator>(false);
    }
    if (archName == "x86_64") {
        return std::make_unique<X86MaskGenerator>(true);
    }

    // ARM
    if (archName == "armv7" || archName == "armv7eb" || archName == "arm") {
        return std::make_unique<ARMMaskGenerator>(false);
    }
    if (archName == "thumb2" || archName == "thumb2eb" || archName == "thumb") {
        return std::make_unique<ARMMaskGenerator>(true);
    }

    // ARM64
    if (archName == "aarch64" || archName == "arm64") {
        return std::make_unique<ARM64MaskGenerator>();
    }

    // Fallback to generic
    return std::make_unique<GenericMaskGenerator>(arch);
}

PatternResult PatternGenerator::generatePattern(FunctionRef func) {
    PatternResult result;
    result.success = false;
    result.func_size = 0;

    if (!m_bv || !func) {
        result.error = "Invalid binary view or function";
        return result;
    }

    // Get function name and address for debug logging
    std::string funcName = func->GetSymbol() ? func->GetSymbol()->GetFullName() : "<unnamed>";
    uint64_t funcAddr = func->GetStart();

    // Create debug dump if enabled
    std::unique_ptr<debug::FunctionDump> dump;
    if (isDebugEnabled()) {
        dump = std::make_unique<debug::FunctionDump>(funcName, funcAddr);
        dump->section("FUNCTION INFO");
        dump->logKeyValue("Name", funcName);
        dump->logKeyValue("Start Address", funcAddr);
        dump->logKeyValue("Architecture", m_maskGen->getName());
    }

    // Get function address ranges and find the full extent
    // IDA includes ALL bytes from function start to end, including alignment NOPs
    // between basic blocks, so we need to do the same
    auto addrRanges = func->GetAddressRanges();
    uint64_t funcStart = func->GetStart();
    uint64_t funcEnd = funcStart;

    // Find the maximum end address across all ranges
    for (const auto& range : addrRanges) {
        if (range.end > funcEnd) {
            funcEnd = range.end;
        }
    }

    // Also check basic blocks in case address ranges are incomplete
    auto blocks = func->GetBasicBlocks();
    std::vector<std::pair<uint64_t, uint64_t>> blockRanges;
    blockRanges.reserve(blocks.size());

    for (auto& block : blocks) {
        blockRanges.emplace_back(block->GetStart(), block->GetEnd());
        if (block->GetEnd() > funcEnd) {
            funcEnd = block->GetEnd();
        }
    }

    std::sort(blockRanges.begin(), blockRanges.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });

    if (dump) {
        dump->logBasicBlocks(blockRanges);
        dump->section("INSTRUCTIONS");
        dump->log("Function range: 0x" + std::to_string(funcStart) + " - 0x" + std::to_string(funcEnd));
        dump->log("Total bytes: " + std::to_string(funcEnd - funcStart));
    }

    // Process ALL bytes from function start to end (not just basic blocks)
    // This includes alignment NOPs between basic blocks, which IDA includes
    // IDA's algorithm:
    // 1. normalized_byte = raw_byte & ~mask_byte
    // 2. hash = MD5(normalized_bytes || mask_bytes)
    std::vector<uint8_t> normalized;
    std::vector<uint8_t> masks;
    auto arch = m_bv->GetDefaultArchitecture();

    // Set function range for the mask generator so it can determine
    // if RIP-relative targets are external references (should be masked)
    // or internal references (should not be masked)
    m_maskGen->setFunctionRange(funcStart, funcEnd);

    // Linear disassembly from funcStart to funcEnd
    uint64_t addr = funcStart;
    while (addr < funcEnd) {
        // Get instruction length
        size_t maxLen = static_cast<size_t>(funcEnd - addr);
        if (maxLen > 16) maxLen = 16;  // Max instruction length

        // Read raw bytes
        BinaryNinja::DataBuffer buf = m_bv->ReadBuffer(addr, maxLen);
        if (buf.GetLength() == 0) {
            addr++;
            continue;
        }

        const uint8_t* data = reinterpret_cast<const uint8_t*>(buf.GetData());
        size_t bufLen = buf.GetLength();

        // Get instruction info for length
        BinaryNinja::InstructionInfo info;
        size_t insnLen = 1;  // Default

        if (arch && arch->GetInstructionInfo(data, addr, bufLen, info)) {
            insnLen = info.length;
            if (insnLen == 0) insnLen = 1;
        }

        if (insnLen > bufLen) insnLen = bufLen;

        // Get raw instruction bytes
        std::vector<uint8_t> rawBytes(data, data + insnLen);

        // Get mask for this instruction
        InstructionMask mask = m_maskGen->getMask(m_bv.GetPtr(), addr, rawBytes);

        // Apply normalization and collect masks (IDA's algorithm)
        std::vector<uint8_t> insnNormalized;
        for (size_t i = 0; i < rawBytes.size(); i++) {
            uint8_t m = (i < mask.mask.size()) ? mask.mask[i] : 0;
            uint8_t n = rawBytes[i] & ~m;  // normalized = raw & ~mask
            normalized.push_back(n);
            masks.push_back(m);
            insnNormalized.push_back(n);
        }

        // Log instruction details
        if (dump) {
            // Get disassembly if available
            std::string disasm;
            if (arch) {
                std::vector<BinaryNinja::InstructionTextToken> tokens;
                if (arch->GetInstructionText(data, addr, insnLen, tokens)) {
                    for (const auto& tok : tokens) {
                        disasm += tok.text;
                    }
                }
            }
            dump->logInstruction(addr, rawBytes, mask.mask, insnNormalized, disasm);
        }

        result.func_size += static_cast<uint32_t>(insnLen);
        addr += insnLen;
    }

    // Compute MD5 hash: MD5(normalized_bytes || mask_bytes)
    // This matches IDA's Lumina hash computation algorithm
    result.normalized = std::move(normalized);
    result.masks = std::move(masks);
    result.hash = computeMD5(result.normalized, result.masks);
    result.success = true;

    // Log final results
    if (dump) {
        dump->logFinalNormalized(result.normalized);
        dump->logHash(result.hash);
        dump->section("SUMMARY");
        dump->logKeyValue("Total bytes", result.func_size);
        dump->logKeyValue("Normalized bytes", (uint64_t)result.normalized.size());
        dump->logKeyValue("Mask bytes", (uint64_t)result.masks.size());
        dump->log("\nHash computed as MD5(normalized || masks) to match IDA");
        dump->log("\nDebug file: " + dump->getFilename());
    }

    if (m_debug) {
        BinaryNinja::LogInfo("PatternGen: %s - %zu bytes, hash: %02x%02x%02x%02x...",
            m_maskGen->getName().c_str(),
            result.normalized.size(),
            result.hash[0], result.hash[1], result.hash[2], result.hash[3]);
    }

    return result;
}

std::array<uint8_t, 16> PatternGenerator::computeMD5(
    const std::vector<uint8_t>& normalized_bytes,
    const std::vector<uint8_t>& mask_bytes)
{
    // IDA's algorithm: MD5(normalized_bytes || mask_bytes)
    // Where normalized_bytes[i] = raw_bytes[i] & ~mask_bytes[i]
    // The hash is computed over the concatenation of:
    // 1. Normalized instruction bytes (position-independent)
    // 2. The mask bytes (indicating which positions were masked)
    QCryptographicHash hash(QCryptographicHash::Md5);
    if (!normalized_bytes.empty()) {
        hash.addData(QByteArrayView(reinterpret_cast<const char*>(normalized_bytes.data()),
                                    qsizetype(normalized_bytes.size())));
    }
    if (!mask_bytes.empty()) {
        hash.addData(QByteArrayView(reinterpret_cast<const char*>(mask_bytes.data()),
                                    qsizetype(mask_bytes.size())));
    }
    QByteArray result = hash.result();

    std::array<uint8_t, 16> out{};
    for (int i = 0; i < 16 && i < result.size(); i++) {
        out[i] = static_cast<uint8_t>(result[i]);
    }
    return out;
}

// ============================================================================
// Convenience Functions
// ============================================================================

std::array<uint8_t, 16> computeCalcRelHash(
    BinaryViewRef bv,
    FunctionRef func)
{
    PatternGenerator gen(bv);
    PatternResult result = gen.generatePattern(func);
    if (result.success) {
        return result.hash;
    }
    return std::array<uint8_t, 16>{};
}

PatternResult computePattern(
    BinaryViewRef bv,
    FunctionRef func)
{
    PatternGenerator gen(bv);
    return gen.generatePattern(func);
}

} // namespace lumina
