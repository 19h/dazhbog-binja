#include "metadatasidebar.h"
// Forward declaration for View class
class View;
#include <QMessageBox>
#include <QHeaderView>
#include <QCryptographicHash>
#include <QProcessEnvironment>
#include <QSysInfo>
#include <sstream>
#include <iomanip>
#include <cstdio>
#include <algorithm>

// Forward declaration
void extractAndLogLuminaMetadata(BinaryViewRef data, ViewFrame* frame = nullptr);

// Build a simple 16-byte fingerprint and TLV payload for a function
static bool collectFunctionBytes(BinaryViewRef bv, FunctionRef func, std::vector<uint8_t>& out) {
	out.clear();
	auto blocks = func->GetBasicBlocks();
	std::vector<std::pair<uint64_t,uint64_t>> ranges; ranges.reserve(blocks.size());
	for (auto& b : blocks) ranges.emplace_back(b->GetStart(), b->GetEnd());
	std::sort(ranges.begin(), ranges.end(), [](auto& a, auto& b){ return a.first < b.first; });
	for (auto& r : ranges) {
		uint64_t start = r.first, end = r.second;
		if (end <= start) continue;
		size_t len = static_cast<size_t>(end - start);
		DataBuffer buf = bv->ReadBuffer(start, len);
		if (buf.GetLength() == 0) continue;
		const uint8_t* p = reinterpret_cast<const uint8_t*>(buf.GetData());
		out.insert(out.end(), p, p + buf.GetLength());
	}
	return true;
}

static std::array<uint8_t,16> md5_of(const std::vector<uint8_t>& bytes) {
	QCryptographicHash h(QCryptographicHash::Md5);
	if (!bytes.empty()) h.addData(QByteArrayView(reinterpret_cast<const char*>(bytes.data()), qsizetype(bytes.size())));
	QByteArray r = h.result();
	std::array<uint8_t,16> a{};
	for (int i=0;i<16 && i<r.size();++i) a[i] = static_cast<uint8_t>(r[i]);
	return a;
}

static lumina::EncodedFunction encodeOneFunction(BinaryViewRef bv, FunctionRef func) {
	lumina::EncodedFunction ef;
	ef.name = func->GetSymbol() ? func->GetSymbol()->GetFullName() : std::string("<unnamed>");
	// func_len metric: total bytes across basic blocks
	std::vector<uint8_t> code;
	if (collectFunctionBytes(bv, func, code)) ef.func_len = static_cast<uint32_t>(code.size());
	else ef.func_len = 0;
	// TLV payload: no-return flag, comment, variable names
	const bool noReturn = !func->CanReturn();
	const std::string comment = func->GetComment();
	std::vector<std::string> varNames;
	auto vars = func->GetVariables();
	varNames.reserve(vars.size());
	for (auto& vPair : vars) varNames.push_back(vPair.second.name);
	ef.func_data = lumina::build_function_tlv(noReturn, comment, varNames);
	// 16-byte fingerprint (assumption: MD5 of concatenated BB bytes)
	ef.hash = md5_of(code);
	ef.unk2 = 0;
	return ef;
}

static std::array<uint8_t,16> md5_zero() {
	std::array<uint8_t,16> z{}; return z;
}

// Compute 16-byte key for a function (MD5 of concatenated BB bytes)
static std::array<uint8_t,16> compute_key(BinaryViewRef bv, FunctionRef func) {
	std::vector<uint8_t> code; 
	collectFunctionBytes(bv, func, code);
	return md5_of(code);
}

// FunctionMetadataModel implementation
FunctionMetadataModel::FunctionMetadataModel(QWidget* parent, BinaryViewRef data)
	: QAbstractTableModel(parent), m_data(data)
{
	refresh();
}

void FunctionMetadataModel::refresh()
{
	beginResetModel();
	m_entries.clear();
	
	if (!m_data)
	{
		endResetModel();
		return;
	}

	// Get all functions
	auto functions = m_data->GetAnalysisFunctionList();
	
	for (auto& func : functions)
	{
		// Check if function has any metadata
		// For demo purposes, we'll check for common metadata keys
		std::vector<std::string> commonKeys = {"comment", "tag", "color", "user_data", "signature"};
		
		FunctionMetadataEntry entry;
		entry.address = func->GetStart();
		entry.name = QString::fromStdString(func->GetSymbol()->GetFullName());
		
		bool hasMetadata = false;
		for (const auto& key : commonKeys)
		{
			auto metadata = func->QueryMetadata(key);
			if (metadata)
			{
				// Try to get string value
				if (metadata->IsString())
				{
					entry.metadata[QString::fromStdString(key)] = 
						QString::fromStdString(metadata->GetString());
					hasMetadata = true;
				}
			}
		}
		
		// Always add entries for demonstration, even without metadata
		// In a real implementation, you might only add functions with metadata
		if (hasMetadata || functions.size() < 50) // Limit display for large binaries
		{
			m_entries.push_back(entry);
		}
	}
	
	endResetModel();
}

int FunctionMetadataModel::columnCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return 4; // Checkbox, Address, Name, Metadata Keys
}

int FunctionMetadataModel::rowCount(const QModelIndex& parent) const
{
	if (parent.isValid())
		return 0;
	return m_entries.size();
}

QVariant FunctionMetadataModel::data(const QModelIndex& index, int role) const
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return QVariant();
	
	const auto& entry = m_entries[index.row()];
	
	if (role == Qt::DisplayRole)
	{
		switch (index.column())
		{
		case 0: // Checkbox column - no display text
			return QVariant();
		case 1: // Address
			return QString("0x%1").arg(entry.address, 0, 16);
		case 2: // Name
			return entry.name;
		case 3: // Metadata keys
			{
				QStringList keys;
				for (auto it = entry.metadata.begin(); it != entry.metadata.end(); ++it)
					keys << it->first;
				return keys.join(", ");
			}
		}
	}
	else if (role == Qt::CheckStateRole && index.column() == 0)
	{
		return entry.selected ? Qt::Checked : Qt::Unchecked;
	}
	else if (role == Qt::TextAlignmentRole && index.column() == 1)
	{
		return QVariant(Qt::AlignRight | Qt::AlignVCenter);
	}
	
	return QVariant();
}

QVariant FunctionMetadataModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (orientation == Qt::Horizontal && role == Qt::DisplayRole)
	{
		switch (section)
		{
		case 0: return "✓";
		case 1: return "Address";
		case 2: return "Function Name";
		case 3: return "Metadata";
		}
	}
	return QVariant();
}

Qt::ItemFlags FunctionMetadataModel::flags(const QModelIndex& index) const
{
	if (!index.isValid())
		return Qt::NoItemFlags;
	
	Qt::ItemFlags flags = QAbstractTableModel::flags(index);
	
	if (index.column() == 0)
		flags |= Qt::ItemIsUserCheckable;
	
	return flags;
}

bool FunctionMetadataModel::setData(const QModelIndex& index, const QVariant& value, int role)
{
	if (!index.isValid() || index.row() >= (int)m_entries.size())
		return false;
	
	if (role == Qt::CheckStateRole && index.column() == 0)
	{
		m_entries[index.row()].selected = (value.toInt() == Qt::Checked);
		emit dataChanged(index, index);
		return true;
	}
	
	return false;
}

void FunctionMetadataModel::selectAll()
{
	for (auto& entry : m_entries)
		entry.selected = true;
	if (!m_entries.empty())
		emit dataChanged(createIndex(0, 0), createIndex(int(m_entries.size()) - 1, 0));
}

void FunctionMetadataModel::selectNone()
{
	for (auto& entry : m_entries)
		entry.selected = false;
	if (!m_entries.empty())
		emit dataChanged(createIndex(0, 0), createIndex(int(m_entries.size()) - 1, 0));
}

std::vector<FunctionMetadataEntry*> FunctionMetadataModel::getSelectedEntries()
{
	std::vector<FunctionMetadataEntry*> selected;
	for (auto& entry : m_entries)
	{
		if (entry.selected)
			selected.push_back(&entry);
	}
	return selected;
}

// FunctionMetadataTableView implementation
FunctionMetadataTableView::FunctionMetadataTableView(QWidget* parent, ViewFrame* frame, BinaryViewRef data)
	: QTableView(parent), m_data(data), m_frame(frame)
{
	m_model = new FunctionMetadataModel(this, data);
	setModel(m_model);
	
	// Configure table appearance
	horizontalHeader()->setStretchLastSection(true);
	horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
	verticalHeader()->setVisible(false);
	setSelectionBehavior(QAbstractItemView::SelectRows);
	setSelectionMode(QAbstractItemView::SingleSelection);
	setSortingEnabled(false);
	setAlternatingRowColors(true);
	
	// Set column widths
	setColumnWidth(0, 30);  // Checkbox
	setColumnWidth(1, 100); // Address
	setColumnWidth(2, 200); // Name
	
	updateFont();
	
	connect(this, &QTableView::doubleClicked, this, &FunctionMetadataTableView::onRowDoubleClicked);
}

void FunctionMetadataTableView::updateFont()
{
	setFont(getMonospaceFont(this));
}

void FunctionMetadataTableView::contextMenuEvent(QContextMenuEvent* event)
{
	QMenu menu(this);
	
	QModelIndex index = indexAt(event->pos());
	if (index.isValid())
	{
		menu.addAction("Navigate to Function", this, &FunctionMetadataTableView::navigateToFunction);
		menu.addAction("Apply Metadata", this, &FunctionMetadataTableView::applyMetadataToSelected);
		menu.addSeparator();
		// Push Selected
		menu.addAction("Push Selected (Lumina)", [this]() {
			auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
			if (p) p->pushSelectedLumina();
		});
	}
	
	menu.addAction("Refresh", [this]() { m_model->refresh(); });
	menu.addAction("Select All", [this]() { m_model->selectAll(); });
	menu.addAction("Select None", [this]() { m_model->selectNone(); });
	
	// Lumina operations
	menu.addSeparator();
	menu.addAction("Push All (Lumina)", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->pushAllLumina();
	});
	menu.addSeparator();
	menu.addAction("Pull Selected (Lumina)", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->pullSelectedLumina();
	});
	menu.addAction("Pull All (Lumina)", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->pullAllLumina();
	});
	menu.addAction("Apply Pulled to Selected", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->applyPulledToSelected();
	});
	menu.addAction("Batch Diff & Apply (Lumina)", [this]() {
		auto p = qobject_cast<FunctionMetadataSidebarWidget*>(parentWidget());
		if (p) p->batchDiffAndApplySelected();
	});
	
	menu.exec(event->globalPos());
}

void FunctionMetadataTableView::onRowDoubleClicked(const QModelIndex& index)
{
	if (!index.isValid() || !m_frame || !m_data)
		return;
	
	const auto& entry = m_model->entryAt(index.row());
	
	// Navigate to the function address
	m_frame->navigate(m_data, entry.address);
}

void FunctionMetadataTableView::applyMetadataToSelected()
{
	QModelIndex index = currentIndex();
	if (!index.isValid())
		return;
	
	const auto& entry = m_model->entryAt(index.row());
	
	QString metadataInfo;
	for (auto it = entry.metadata.begin(); it != entry.metadata.end(); ++it)
	{
		metadataInfo += QString("%1: %2\n").arg(it->first, it->second);
	}
	
	QMessageBox::information(this, "Function Metadata",
		QString("Function: %1\nAddress: 0x%2\n\nMetadata:\n%3")
			.arg(entry.name)
			.arg(entry.address, 0, 16)
			.arg(metadataInfo.isEmpty() ? "No metadata" : metadataInfo));
}

void FunctionMetadataTableView::navigateToFunction()
{
	QModelIndex index = currentIndex();
	if (index.isValid())
		onRowDoubleClicked(index);
}

// FunctionMetadataSidebarWidget implementation
FunctionMetadataSidebarWidget::FunctionMetadataSidebarWidget(ViewFrame* frame, BinaryViewRef data)
	: SidebarWidget("Function Metadata"), m_data(data), m_frame(frame)
{
	QVBoxLayout* layout = new QVBoxLayout(this);
	layout->setContentsMargins(0, 0, 0, 0);
	layout->setSpacing(0);
	
	// Create table
	m_table = new FunctionMetadataTableView(this, frame, data);
	m_model = static_cast<FunctionMetadataModel*>(m_table->model());
	layout->addWidget(m_table, 1);
	
	// Create button bar
	QWidget* buttonBar = new QWidget(this);
	QHBoxLayout* buttonLayout = new QHBoxLayout(buttonBar);
	buttonLayout->setContentsMargins(4, 4, 4, 4);
	
	m_refreshButton = new QPushButton("Refresh", buttonBar);
	m_rejectAllButton = new QPushButton("Reject All", buttonBar);
	m_applySelectedButton = new QPushButton("Apply Selected", buttonBar);
	m_applyAllButton = new QPushButton("Apply All", buttonBar);
	// Lumina push/pull buttons
	m_pushSelected = new QPushButton("Push Selected (Lumina)", buttonBar);
	m_pushAll = new QPushButton("Push All (Lumina)", buttonBar);
	m_pullSelected = new QPushButton("Pull Selected (Lumina)", buttonBar);
	m_applyPulled = new QPushButton("Apply Pulled", buttonBar);
	QPushButton* batchBtn = new QPushButton("Batch Diff & Apply", buttonBar);
	
	buttonLayout->addWidget(m_refreshButton);
	buttonLayout->addStretch();
	buttonLayout->addWidget(m_rejectAllButton);
	buttonLayout->addWidget(m_applySelectedButton);
	buttonLayout->addWidget(m_applyAllButton);
	buttonLayout->addWidget(m_pushSelected);
	buttonLayout->addWidget(m_pushAll);
	buttonLayout->addWidget(m_pullSelected);
	buttonLayout->addWidget(m_applyPulled);
	buttonLayout->addWidget(batchBtn);
	
	layout->addWidget(buttonBar);
	
	// Connect buttons
	connect(m_refreshButton, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::refreshMetadata);
	connect(m_rejectAllButton, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::rejectAll);
	connect(m_applySelectedButton, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::applySelected);
	connect(m_applyAllButton, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::applyAll);
	connect(m_pushSelected, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::pushSelectedLumina);
	connect(m_pushAll, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::pushAllLumina);
	connect(m_pullSelected, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::pullSelectedLumina);
	connect(m_applyPulled, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::applyPulledToSelected);
	connect(batchBtn, &QPushButton::clicked, this, &FunctionMetadataSidebarWidget::batchDiffAndApplySelected);
	
	setLayout(layout);
}

void FunctionMetadataSidebarWidget::notifyViewChanged(ViewFrame* frame)
{
	m_frame = frame;
	if (frame)
	{
		// Update m_data from the current view in the frame
		auto view = frame->getCurrentViewInterface();
		if (view)
		{
			m_data = view->getData();
		}
	}
	
	// Refresh the model silently (without triggering Lumina extraction)
	if (m_model && m_data)
		m_model->refresh();
}

void FunctionMetadataSidebarWidget::notifyFontChanged()
{
	m_table->updateFont();
}

void FunctionMetadataSidebarWidget::refreshMetadata()
{
	if (m_model)
		m_model->refresh();
	
	// LUMINA EXTRACTION: Extract and log metadata for current function when Refresh is clicked
	if (m_data)
	{
		BinaryNinja::LogInfo(">>> Refresh button clicked - extracting Lumina metadata...");
		extractAndLogLuminaMetadata(m_data, m_frame);
	}
}

void FunctionMetadataSidebarWidget::rejectAll()
{
	m_model->selectNone();
	QMessageBox::information(this, "Reject All", "All metadata entries deselected.");
}

void FunctionMetadataSidebarWidget::applySelected()
{
	auto selected = m_model->getSelectedEntries();
	
	if (selected.empty())
	{
		QMessageBox::information(this, "Apply Selected", "No entries selected.");
		return;
	}
	
	QString message = QString("Would apply metadata to %1 selected function(s):\n\n").arg(selected.size());
	
	int count = 0;
	for (auto* entry : selected)
	{
		message += QString("• %1 (0x%2)\n").arg(entry->name).arg(entry->address, 0, 16);
		if (++count >= 10)
		{
			message += QString("... and %1 more\n").arg(selected.size() - 10);
			break;
		}
	}
	
	QMessageBox::information(this, "Apply Selected", message);
}

void FunctionMetadataSidebarWidget::applyAll()
{
	int total = m_model->rowCount();
	
	QString message = QString("Would apply metadata to all %1 function(s) in the table.").arg(total);
	QMessageBox::information(this, "Apply All", message);
}

void FunctionMetadataSidebarWidget::pushSelectedLumina()
{
	if (!m_data) { QMessageBox::warning(this, "Lumina Push", "No BinaryView"); return; }
	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) { QMessageBox::information(this, "Lumina Push", "No entries selected."); return; }

	// Map address -> FunctionRef
	std::unordered_map<uint64_t, FunctionRef> fbyAddr;
	for (auto& f : m_data->GetAnalysisFunctionList()) fbyAddr.emplace(f->GetStart(), f);

	std::vector<lumina::EncodedFunction> funcs;
	funcs.reserve(selected.size());
	for (auto* e : selected) {
		auto it = fbyAddr.find(e->address);
		if (it == fbyAddr.end()) continue;
		funcs.push_back(encodeOneFunction(m_data, it->second));
	}

	if (funcs.empty()) { QMessageBox::information(this, "Lumina Push", "No functions resolved."); return; }

	// Build legacy Hello + PushMetadata payloads
	auto hello = lumina::encode_hello_payload(5);
	std::string idbPath = "<bn>";
	std::string filePath = "<unknown>";
	std::string hostName = QSysInfo::machineHostName().toStdString();
	auto push = lumina::encode_push_payload(/*unk0=*/0, idbPath, filePath, md5_zero(), hostName, funcs, {});

	// Resolve server from env or defaults
	QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
	QString host = env.contains("BN_LUMINA_HOST") ? env.value("BN_LUMINA_HOST") : QStringLiteral("127.0.0.1");
	quint16 port = env.contains("BN_LUMINA_PORT") ? env.value("BN_LUMINA_PORT").toUShort() : 20667;

	lumina::Client cli(host, port, this);
	QString err;
	std::vector<uint32_t> statuses;
	if (!cli.helloAndPush(hello, push, &err, &statuses, 8000)) {
		QMessageBox::critical(this, "Lumina Push", QString("Failed: %1").arg(err));
		return;
	}

	// Report: 1=new unique, 0=updated (per your server)
	size_t news = 0, updates = 0;
	for (uint32_t s : statuses) (s > 0 ? news : updates)++;
	QMessageBox::information(this, "Lumina Push",
		QString("Pushed %1 function(s): %2 new, %3 updated")
			.arg(statuses.size()).arg(news).arg(updates));
}

void FunctionMetadataSidebarWidget::pushAllLumina()
{
	// Select all rows, reuse pushSelectedLumina
	m_model->selectAll();
	pushSelectedLumina();
}

void FunctionMetadataSidebarWidget::pullSelectedLumina()
{
	if (!m_data) { QMessageBox::warning(this, "Lumina Pull", "No BinaryView"); return; }

	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) { QMessageBox::information(this, "Lumina Pull", "No entries selected."); return; }

	// Map function start -> FunctionRef
	std::unordered_map<uint64_t, FunctionRef> fbyAddr;
	for (auto& f : m_data->GetAnalysisFunctionList()) fbyAddr.emplace(f->GetStart(), f);

	// Build hash list in the same order as 'selected'
	std::vector<std::array<uint8_t,16>> hashes;
	std::vector<uint64_t> addrs;
	hashes.reserve(selected.size());
	addrs.reserve(selected.size());
	for (auto* e : selected) {
		auto it = fbyAddr.find(e->address);
		if (it == fbyAddr.end()) continue;
		hashes.push_back(compute_key(m_data, it->second));
		addrs.push_back(e->address);
	}
	if (hashes.empty()) { QMessageBox::information(this, "Lumina Pull", "No functions resolved."); return; }

	// Build request
	auto hello = lumina::encode_hello_payload(5);
	auto pull = lumina::encode_pull_payload(0, hashes);

	// Resolve server (env or default)
	QProcessEnvironment env = QProcessEnvironment::systemEnvironment();
	QString host = env.contains("BN_LUMINA_HOST") ? env.value("BN_LUMINA_HOST") : QStringLiteral("127.0.0.1");
	quint16 port = env.contains("BN_LUMINA_PORT") ? env.value("BN_LUMINA_PORT").toUShort() : 20667;

	lumina::Client cli(host, port, this);
	QString err;
	std::vector<uint32_t> statuses;
	std::vector<lumina::PulledFunction> funcs;
	if (!cli.helloAndPull(hello, pull, &err, &statuses, &funcs, 12000)) {
		QMessageBox::critical(this, "Lumina Pull", QString("Failed: %1").arg(err));
		return;
	}

	// Map results: statuses length == queries; funcs contains only found entries in order
	size_t fi = 0, found = 0;
	for (size_t i = 0; i < statuses.size() && i < addrs.size(); ++i) {
		if (statuses[i] == 0) {
			if (fi >= funcs.size()) break;
			const auto& mf = funcs[fi++];
			lumina::ParsedTLV tlv;
			if (!lumina::parse_function_tlv(mf.data, &tlv)) {
				BinaryNinja::LogWarn("Lumina TLV parse failed for addr 0x%llx", (unsigned long long)addrs[i]);
				continue;
			}
			PullCacheEntry pc;
			pc.have = true;
			pc.tlv = std::move(tlv);
			pc.popularity = mf.popularity;
			pc.len = mf.len;
			pc.remoteName = mf.name;
			pc.raw = mf.data;
			m_pullCache[addrs[i]] = std::move(pc);
			found++;
		}
	}

	QMessageBox::information(this, "Lumina Pull",
		QString("Requested %1 function(s).\nFound %2; updated cache for selected rows.")
			.arg(hashes.size()).arg(found));
}

void FunctionMetadataSidebarWidget::pullAllLumina()
{
	m_model->selectAll();
	pullSelectedLumina();
}

void FunctionMetadataSidebarWidget::applyPulledToSelected()
{
	if (!m_data) return;
	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) {
		QMessageBox::information(this, "Apply Pulled", "No entries selected.");
		return;
	}

	// Function lookup
	std::unordered_map<uint64_t, FunctionRef> fbyAddr;
	for (auto& f : m_data->GetAnalysisFunctionList()) fbyAddr.emplace(f->GetStart(), f);

	size_t applied = 0, missing = 0;
	for (auto* e : selected) {
		auto cit = m_pullCache.find(e->address);
		if (cit == m_pullCache.end() || !cit->second.have) { missing++; continue; }
		auto fit = fbyAddr.find(e->address);
		if (fit == fbyAddr.end()) { missing++; continue; }
		FunctionRef func = fit->second;

		// Apply comment
		if (!cit->second.tlv.comment.empty()) {
			func->SetComment(cit->second.tlv.comment);
		}

		// Apply no-return (if present)
		if (cit->second.tlv.hasNoReturn) {
			bool desiredNoRet = cit->second.tlv.noReturn;
			bool currentNoRet = !func->CanReturn();
			if (desiredNoRet != currentNoRet) {
				func->SetCanReturn(!desiredNoRet);
			}
		}

		// (Optional) variables: showing only in log for now
		if (!cit->second.tlv.varNames.empty()) {
			BinaryNinja::LogInfo("Lumina vars for 0x%llx: %zu items",
				(unsigned long long)e->address, cit->second.tlv.varNames.size());
		}

		applied++;
	}

	QMessageBox::information(this, "Apply Pulled",
		QString("Applied metadata to %1 function(s); %2 missing cached data.")
			.arg(applied).arg(missing));
}

void FunctionMetadataSidebarWidget::batchDiffAndApplySelected()
{
	if (!m_data) { QMessageBox::warning(this, "Lumina", "No BinaryView"); return; }
	auto selected = m_model->getSelectedEntries();
	if (selected.empty()) { QMessageBox::information(this, "Lumina", "No entries selected."); return; }

	// Build address->FunctionRef map
	std::unordered_map<uint64_t, FunctionRef> fbyAddr;
	for (auto& f : m_data->GetAnalysisFunctionList()) fbyAddr.emplace(f->GetStart(), f);

	// Build rows from cache + local
	std::vector<LuminaBulkDiffRow> rows;
	rows.reserve(selected.size());

	size_t missing = 0;
	for (auto* e : selected) {
		auto cit = m_pullCache.find(e->address);
		if (cit == m_pullCache.end() || !cit->second.have) { missing++; continue; }
		auto fit = fbyAddr.find(e->address);
		if (fit == fbyAddr.end()) { missing++; continue; }

		FunctionRef func = fit->second;
		LuminaBulkDiffRow row;
		row.address = e->address;
		row.localName = QString::fromStdString(func->GetSymbol() ? func->GetSymbol()->GetFullName() : std::string("<unnamed>"));
		row.remoteName = QString::fromStdString(cit->second.remoteName);
		row.localComment = QString::fromStdString(func->GetComment());
		row.remoteComment = QString::fromStdString(cit->second.tlv.comment);
		row.localNoRet = !func->CanReturn();
		row.remoteNoRet = cit->second.tlv.hasNoReturn ? cit->second.tlv.noReturn : row.localNoRet;

		// default: check only when different
		row.applyComment  = (row.localComment != row.remoteComment);
		row.applyNoReturn = (row.localNoRet  != row.remoteNoRet);
		rows.push_back(std::move(row));
	}

	if (rows.empty()) {
		QMessageBox::information(this, "Lumina",
			QString("No cached pulled data for selected rows (missing=%1).").arg(missing));
		return;
	}

	LuminaBulkDiffDialog dlg(this, std::move(rows));
	if (dlg.exec() != QDialog::Accepted) return;

	// Apply selections
	const auto& outRows = dlg.rows();
	size_t applied = 0;
	for (const auto& r : outRows) {
		auto fit = fbyAddr.find(r.address);
		if (fit == fbyAddr.end()) continue;
		FunctionRef func = fit->second;

		bool changed = false;
		if (r.applyComment && (r.localComment != r.remoteComment)) {
			func->SetComment(r.remoteComment.toStdString());
			changed = true;
		}
		if (r.applyNoReturn && (r.localNoRet != r.remoteNoRet)) {
			func->SetCanReturn(!r.remoteNoRet);
			changed = true;
		}
		if (changed) applied++;
	}

	QMessageBox::information(this, "Lumina",
		QString("Applied changes to %1 function(s). Missing cache: %2").arg(applied).arg(missing));
}

// FunctionMetadataSidebarWidgetType implementation
FunctionMetadataSidebarWidgetType::FunctionMetadataSidebarWidgetType()
	: SidebarWidgetType(QImage(), "Function Metadata")
{
}

SidebarWidget* FunctionMetadataSidebarWidgetType::createWidget(ViewFrame* frame, BinaryViewRef data)
{
	return new FunctionMetadataSidebarWidget(frame, data);
}

// Lumina metadata extraction and logging
void extractAndLogLuminaMetadata(BinaryViewRef data, ViewFrame* frame)
{
	// Print to both stderr (terminal) and Binary Ninja log
	fprintf(stderr, "\n========================================\n");
	fprintf(stderr, "LUMINA METADATA EXTRACTION STARTED\n");
	fprintf(stderr, "========================================\n");

	if (!data)
	{
		fprintf(stderr, "ERROR: No binary view available\n");
		BinaryNinja::LogInfo("No binary view available");
		return;
	}

	auto functions = data->GetAnalysisFunctionList();
	if (functions.empty())
	{
		fprintf(stderr, "ERROR: No functions found in binary\n");
		BinaryNinja::LogInfo("No functions found in binary");
		return;
	}

	// Get the current function if available, otherwise use the first function
	FunctionRef func;
	uint64_t funcStart;
	if (frame)
	{
		View* currentView = frame->getCurrentViewInterface();
		if (currentView && currentView->getCurrentFunction())
		{
			func = currentView->getCurrentFunction();
			funcStart = func->GetStart();
			fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR CURRENT FUNCTION ===\n");
			fprintf(stderr, "Function Address: 0x%lx\n", funcStart);
			BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR CURRENT FUNCTION ===");
			BinaryNinja::LogInfo("Function Address: 0x%lx", funcStart);
		}
		else
		{
			// Fallback to first function if no current function
			func = functions[0];
			funcStart = func->GetStart();
			fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no current function) ===\n");
			fprintf(stderr, "Function Address: 0x%lx\n", funcStart);
			BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no current function) ===");
			BinaryNinja::LogInfo("Function Address: 0x%lx", funcStart);
		}
	}
	else
	{
		// Fallback to first function if no frame
		func = functions[0];
		funcStart = func->GetStart();
		fprintf(stderr, "\n=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no frame) ===\n");
		fprintf(stderr, "Function Address: 0x%lx\n", funcStart);
		BinaryNinja::LogInfo("=== LUMINA METADATA EXTRACTION FOR FIRST FUNCTION (no frame) ===");
		BinaryNinja::LogInfo("Function Address: 0x%lx", funcStart);
	}
	
	// 1. FUNCTION IDENTITY
	auto symbol = func->GetSymbol();
	std::string funcName = symbol ? symbol->GetFullName() : "<unnamed>";
	fprintf(stderr, "\n[1] FUNCTION IDENTITY:\n");
	fprintf(stderr, "  Name: %s\n", funcName.c_str());
	fprintf(stderr, "  Start: 0x%lx\n", funcStart);
	uint64_t funcSize = func->GetHighestAddress() - funcStart;
	fprintf(stderr, "  Size: %lu bytes (approx)\n", funcSize);
	
	BinaryNinja::LogInfo("[1] FUNCTION IDENTITY:");
	BinaryNinja::LogInfo("  Name: %s", funcName.c_str());
	BinaryNinja::LogInfo("  Start: 0x%lx", funcStart);
	BinaryNinja::LogInfo("  Size: %lu bytes (approx)", funcSize);
	
	// 2. FUNCTION TYPE INFO (Tag 1)
	fprintf(stderr, "\n[2] FUNCTION TYPE INFO (TLV Tag 1):\n");
	fprintf(stderr, "  No-return flag: %s\n", func->CanReturn() ? "false" : "true");
	BinaryNinja::LogInfo("[2] FUNCTION TYPE INFO (TLV Tag 1):");
	BinaryNinja::LogInfo("  No-return flag: %s", func->CanReturn() ? "false" : "true");
	
	// 3. FUNCTION COMMENTS (Tags 3, 4)
	fprintf(stderr, "\n[3] FUNCTION COMMENTS (TLV Tags 3, 4):\n");
	std::string funcComment = func->GetComment();
	if (!funcComment.empty())
	{
		fprintf(stderr, "  Function comment: %s\n", funcComment.c_str());
		BinaryNinja::LogInfo("  Function comment: %s", funcComment.c_str());
	}
	else
	{
		fprintf(stderr, "  No function comment\n");
		BinaryNinja::LogInfo("  No function comment");
	}
	
	// 4. BASIC BLOCKS INFO
	fprintf(stderr, "\n[4] BASIC BLOCKS:\n");
	auto blocks = func->GetBasicBlocks();
	fprintf(stderr, "  Block count: %zu\n", blocks.size());
	BinaryNinja::LogInfo("[4] BASIC BLOCKS:");
	BinaryNinja::LogInfo("  Block count: %zu", blocks.size());
	
	for (size_t i = 0; i < std::min((size_t)3, blocks.size()); i++)
	{
		auto block = blocks[i];
		uint64_t blockSize = block->GetEnd() - block->GetStart();
		fprintf(stderr, "    Block %zu: 0x%lx - 0x%lx (%lu bytes)\n",
		        i, block->GetStart(), block->GetEnd(), blockSize);
		BinaryNinja::LogInfo("    Block %zu: 0x%lx - 0x%lx (%lu bytes)",
		        i, block->GetStart(), block->GetEnd(), blockSize);
	}
	
	// 5. VARIABLES
	fprintf(stderr, "\n[5] STACK FRAME / VARIABLES (TLV Tag 9):\n");
	auto vars = func->GetVariables();
	fprintf(stderr, "  Variable count: %zu\n", vars.size());
	BinaryNinja::LogInfo("[5] STACK FRAME / VARIABLES (TLV Tag 9):");
	BinaryNinja::LogInfo("  Variable count: %zu", vars.size());
	
	// 6. CROSS REFERENCES
	fprintf(stderr, "\n[6] CROSS REFERENCES:\n");
	auto callSites = func->GetCallSites();
	fprintf(stderr, "  Call sites: %zu locations\n", callSites.size());
	BinaryNinja::LogInfo("[6] CROSS REFERENCES:");
	BinaryNinja::LogInfo("  Call sites: %zu locations", callSites.size());

	// 7. DECOMPILED CODE (HLIL)
	fprintf(stderr, "\n[7] DECOMPILED CODE (HLIL):\n");
	auto hlil = func->GetHighLevelIL();
	if (hlil)
	{
		// Get the root expression index directly using C API
		size_t rootExprIndex = BNGetHighLevelILRootExpr(hlil->GetObject());
		auto lines = hlil->GetExprText(rootExprIndex);
		std::string hlilStr;
		for (const auto& line : lines)
		{
			for (const auto& token : line.tokens)
			{
				hlilStr += token.text;
			}
			hlilStr += "\n";
		}
		fprintf(stderr, "  HLIL Code:\n%s", hlilStr.c_str());
		BinaryNinja::LogInfo("[7] DECOMPILED CODE (HLIL):");
		BinaryNinja::LogInfo("  HLIL Code:\n%s", hlilStr.c_str());
	}
	else
	{
		fprintf(stderr, "  No HLIL available\n");
		BinaryNinja::LogInfo("[7] DECOMPILED CODE (HLIL):");
		BinaryNinja::LogInfo("  No HLIL available");
	}

	// 8. ENCODED FUNCTION PAYLOAD (Hexdump)
	fprintf(stderr, "\n[8] ENCODED FUNCTION PAYLOAD (TLV):\n");
	BinaryNinja::LogInfo("[8] ENCODED FUNCTION PAYLOAD (TLV):");
	
	auto encodedFunc = encodeOneFunction(data, func);
	const auto& payload = encodedFunc.func_data;
	
	if (!payload.empty())
	{
		fprintf(stderr, "  Payload size: %zu bytes\n", payload.size());
		fprintf(stderr, "  Hexdump:\n");
		BinaryNinja::LogInfo("  Payload size: %zu bytes", payload.size());
		BinaryNinja::LogInfo("  Hexdump:");
		
		// Print hexdump in standard format: offset | hex bytes | ASCII
		const size_t bytesPerLine = 16;
		for (size_t i = 0; i < payload.size(); i += bytesPerLine)
		{
			// Print offset
			char line[256];
			int pos = snprintf(line, sizeof(line), "    %08zx  ", i);
			
			// Print hex bytes
			size_t lineEnd = std::min(i + bytesPerLine, payload.size());
			for (size_t j = i; j < lineEnd; j++)
			{
				pos += snprintf(line + pos, sizeof(line) - pos, "%02x ", payload[j]);
				if ((j - i) == 7) // Extra space in the middle
				{
					pos += snprintf(line + pos, sizeof(line) - pos, " ");
				}
			}
			
			// Pad if incomplete line
			for (size_t j = lineEnd; j < i + bytesPerLine; j++)
			{
				pos += snprintf(line + pos, sizeof(line) - pos, "   ");
				if ((j - i) == 7)
				{
					pos += snprintf(line + pos, sizeof(line) - pos, " ");
				}
			}
			
			// Print ASCII representation
			pos += snprintf(line + pos, sizeof(line) - pos, " |");
			for (size_t j = i; j < lineEnd; j++)
			{
				unsigned char c = payload[j];
				pos += snprintf(line + pos, sizeof(line) - pos, "%c", (c >= 32 && c <= 126) ? c : '.');
			}
			pos += snprintf(line + pos, sizeof(line) - pos, "|");
			
			fprintf(stderr, "%s\n", line);
			BinaryNinja::LogInfo("%s", line);
		}
		
		fprintf(stderr, "  MD5 Hash: ");
		BinaryNinja::LogInfo("  MD5 Hash: ");
		std::string hashStr;
		for (size_t i = 0; i < encodedFunc.hash.size(); i++)
		{
			char hexByte[4];
			snprintf(hexByte, sizeof(hexByte), "%02x", encodedFunc.hash[i]);
			hashStr += hexByte;
		}
		fprintf(stderr, "%s\n", hashStr.c_str());
		BinaryNinja::LogInfo("%s", hashStr.c_str());
		
		fprintf(stderr, "  Function Length: %u bytes\n", encodedFunc.func_len);
		BinaryNinja::LogInfo("  Function Length: %u bytes", encodedFunc.func_len);
	}
	else
	{
		fprintf(stderr, "  No payload data\n");
		BinaryNinja::LogInfo("  No payload data");
	}

	fprintf(stderr, "\n=== END LUMINA METADATA EXTRACTION ===\n");
	fprintf(stderr, "Plugin successfully extracted basic Lumina-relevant metadata\n");
	fprintf(stderr, "========================================\n\n");
	fflush(stderr);

	BinaryNinja::LogInfo("=== END LUMINA METADATA EXTRACTION ===");
	BinaryNinja::LogInfo("Plugin successfully extracted basic Lumina-relevant metadata");
}

// Plugin initialization
extern "C"
{
	BN_DECLARE_UI_ABI_VERSION
	
	BINARYNINJAPLUGIN bool UIPluginInit()
	{
		// Register the sidebar widget type
		Sidebar::addSidebarWidgetType(new FunctionMetadataSidebarWidgetType());
		
		// Extract and log Lumina metadata for first function on startup
		// (will run when first binary is opened)
		LogInfo("Function Metadata Sidebar plugin loaded - will extract Lumina metadata on first use");
		
		return true;
	}
}

