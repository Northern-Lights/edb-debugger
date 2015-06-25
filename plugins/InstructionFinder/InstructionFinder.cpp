#include "InstructionFinder.h"
#include "edb.h"
#include "dialoginstructionfinder.h"

#include <QMenu>
#include <QList>
#include <QAction>

//InstructionFinder::InstructionFinder(QObject *parent) :
//    QGenericPlugin(parent)
//{
//}

namespace InstructionFinder {

InstructionFinder::InstructionFinder() : menu_(0), dialog_(0) {

}

InstructionFinder::~InstructionFinder() {
    delete dialog_;
}

//------------------------------------------------------------------------------
// Name: menu
// Desc: Adds an option in the right-click menu to open this plugin.
//-----------------------------------------------------------------------------
QMenu *InstructionFinder::menu(QWidget *parent) {
    Q_ASSERT(parent);

    if (!menu_) {
        menu_ = new QMenu(tr("InstructionFinder"), parent);
        menu_->addAction(tr("Find &Instructions"), this, SLOT(show_menu()), QKeySequence(tr("Ctrl+I")));
    }

    return menu_;
}

void InstructionFinder::show_menu() {
    if (!dialog_) {
        dialog_ = new DialogInstructionFinder(edb::v1::debugger_ui);
    }

    dialog_->show();
}

#if QT_VERSION < 0x050000
Q_EXPORT_PLUGIN2(InstructionFinder, InstructionFinder)
#endif // QT_VERSION < 0x050000

}
