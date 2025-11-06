#include "bulkdiffdialog.h"

static constexpr int COL_ADDR  = 0;
static constexpr int COL_LNAME = 1;
static constexpr int COL_RNAME = 2;
static constexpr int COL_LNRET = 3;
static constexpr int COL_RNRET = 4;
static constexpr int COL_LCOMM = 5;
static constexpr int COL_RCOMM = 6;
static constexpr int COL_ACOMM = 7;  // checkbox
static constexpr int COL_ANRET = 8;  // checkbox

QString LuminaBulkDiffDialog::trunc(const QString& s)
{
    constexpr int kMax = 120;
    if (s.size() <= kMax) return s;
    return s.left(kMax) + QStringLiteral(" …");
}

LuminaBulkDiffDialog::LuminaBulkDiffDialog(QWidget* parent,
                                           std::vector<LuminaBulkDiffRow> rows)
    : QDialog(parent), m_rows(std::move(rows))
{
    setWindowTitle("Lumina: Batch Diff & Apply");
    resize(1100, 600);

    m_table = new QTableWidget(this);
    m_table->setColumnCount(9);
    QStringList headers;
    headers << "Address" << "Local Name" << "Remote Name"
            << "Local NoRet" << "Remote NoRet"
            << "Local Comment" << "Remote Comment"
            << "Apply Comment" << "Apply NoRet";
    m_table->setHorizontalHeaderLabels(headers);
    m_table->horizontalHeader()->setStretchLastSection(false);
    m_table->horizontalHeader()->setSectionResizeMode(COL_ADDR,  QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(COL_LNAME, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(COL_RNAME, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(COL_LNRET, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(COL_RNRET, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(COL_LCOMM, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(COL_RCOMM, QHeaderView::Stretch);
    m_table->horizontalHeader()->setSectionResizeMode(COL_ACOMM, QHeaderView::ResizeToContents);
    m_table->horizontalHeader()->setSectionResizeMode(COL_ANRET, QHeaderView::ResizeToContents);
    m_table->verticalHeader()->setVisible(false);
    m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_table->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_table->setAlternatingRowColors(true);
    m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);

    buildTable();

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, this);
    connect(buttons, &QDialogButtonBox::accepted, this, &LuminaBulkDiffDialog::onAccept);
    connect(buttons, &QDialogButtonBox::rejected, this, &LuminaBulkDiffDialog::reject);

    auto* btnAll  = new QPushButton("Select All", this);
    auto* btnNone = new QPushButton("Select None", this);
    auto* btnDiff = new QPushButton("Check DIFF", this);
    connect(btnAll,  &QPushButton::clicked, this, &LuminaBulkDiffDialog::selectAll);
    connect(btnNone, &QPushButton::clicked, this, &LuminaBulkDiffDialog::selectNone);
    connect(btnDiff, &QPushButton::clicked, this, &LuminaBulkDiffDialog::checkDiffOnly);

    auto* hl = new QHBoxLayout;
    hl->addWidget(btnAll);
    hl->addWidget(btnNone);
    hl->addWidget(btnDiff);
    hl->addStretch();

    auto* top = new QVBoxLayout(this);
    top->addWidget(m_table);
    top->addLayout(hl);
    top->addWidget(buttons);
    setLayout(top);
}

void LuminaBulkDiffDialog::buildTable()
{
    m_table->setRowCount(int(m_rows.size()));
    for (int r = 0; r < int(m_rows.size()); ++r) {
        const auto& row = m_rows[std::size_t(r)];

        auto* addr = new QTableWidgetItem(QString("0x%1").arg(row.address, 0, 16));
        auto* lname = new QTableWidgetItem(row.localName);
        auto* rname = new QTableWidgetItem(row.remoteName);
        auto* lnr = new QTableWidgetItem(yesNo(row.localNoRet));
        auto* rnr = new QTableWidgetItem(yesNo(row.remoteNoRet));

        auto* lcomm = new QTableWidgetItem(trunc(row.localComment));
        lcomm->setToolTip(row.localComment);
        auto* rcomm = new QTableWidgetItem(trunc(row.remoteComment));
        rcomm->setToolTip(row.remoteComment);

        auto* acomm = new QTableWidgetItem();
        acomm->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        acomm->setCheckState(row.applyComment ? Qt::Checked : Qt::Unchecked);

        auto* anret = new QTableWidgetItem();
        anret->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled | Qt::ItemIsSelectable);
        anret->setCheckState(row.applyNoReturn ? Qt::Checked : Qt::Unchecked);

        m_table->setItem(r, COL_ADDR,  addr);
        m_table->setItem(r, COL_LNAME, lname);
        m_table->setItem(r, COL_RNAME, rname);
        m_table->setItem(r, COL_LNRET, lnr);
        m_table->setItem(r, COL_RNRET, rnr);
        m_table->setItem(r, COL_LCOMM, lcomm);
        m_table->setItem(r, COL_RCOMM, rcomm);
        m_table->setItem(r, COL_ACOMM, acomm);
        m_table->setItem(r, COL_ANRET, anret);

        // highlight DIFF cells
        if (row.localComment != row.remoteComment)
            rcomm->setForeground(QBrush(QColor(180, 0, 0)));
        if (row.localNoRet != row.remoteNoRet)
            rnr->setForeground(QBrush(QColor(180, 0, 0)));
    }
}

void LuminaBulkDiffDialog::onAccept()
{
    // Read user selections back into m_rows
    for (int r = 0; r < m_table->rowCount(); ++r) {
        auto& row = m_rows[std::size_t(r)];
        auto* acomm = m_table->item(r, COL_ACOMM);
        auto* anret = m_table->item(r, COL_ANRET);
        row.applyComment = (acomm && acomm->checkState() == Qt::Checked);
        row.applyNoReturn = (anret && anret->checkState() == Qt::Checked);
    }
    accept();
}

void LuminaBulkDiffDialog::selectAll()
{
    for (int r = 0; r < m_table->rowCount(); ++r) {
        auto* acomm = m_table->item(r, COL_ACOMM);
        auto* anret = m_table->item(r, COL_ANRET);
        if (acomm) acomm->setCheckState(Qt::Checked);
        if (anret) anret->setCheckState(Qt::Checked);
    }
}

void LuminaBulkDiffDialog::selectNone()
{
    for (int r = 0; r < m_table->rowCount(); ++r) {
        auto* acomm = m_table->item(r, COL_ACOMM);
        auto* anret = m_table->item(r, COL_ANRET);
        if (acomm) acomm->setCheckState(Qt::Unchecked);
        if (anret) anret->setCheckState(Qt::Unchecked);
    }
}

void LuminaBulkDiffDialog::checkDiffOnly()
{
    for (int r = 0; r < m_table->rowCount(); ++r) {
        const auto& row = m_rows[std::size_t(r)];
        const bool cDiff = (row.localComment != row.remoteComment);
        const bool nDiff = (row.localNoRet  != row.remoteNoRet);
        auto* acomm = m_table->item(r, COL_ACOMM);
        auto* anret = m_table->item(r, COL_ANRET);
        if (acomm) acomm->setCheckState(cDiff ? Qt::Checked : Qt::Unchecked);
        if (anret) anret->setCheckState(nDiff ? Qt::Checked : Qt::Unchecked);
    }
}

