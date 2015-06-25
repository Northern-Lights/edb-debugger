#ifndef INSTRUCTIONFINDER_H
#define INSTRUCTIONFINDER_H

#include "IPlugin.h"

class QMenu;
class QDialog;

namespace InstructionFinder {

class InstructionFinder : public QObject, public IPlugin
{
    Q_OBJECT
    Q_INTERFACES(IPlugin)
#if QT_VERSION >= 0x050000
    Q_PLUGIN_METADATA(IID "edb.IPlugin/1.0")
#endif // QT_VERSION >= 0x050000
    Q_CLASSINFO("author", "Armen Boursalian")
    Q_CLASSINFO("url", "http://github.com/Northern-Lights")

public:
    InstructionFinder();
    virtual ~InstructionFinder();

public:
    virtual QMenu *menu(QWidget *parent = 0);

public Q_SLOTS:
    void show_menu();

private:
    QMenu   *menu_;
    QDialog *dialog_;
};

}

#endif // INSTRUCTIONFINDER_H
