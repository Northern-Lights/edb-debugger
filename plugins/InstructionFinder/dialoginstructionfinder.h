#ifndef DIALOGINSTRUCTIONFINDER_H
#define DIALOGINSTRUCTIONFINDER_H

#include <QDialog>
#include <QListWidgetItem>

#include "edb.h"

namespace Ui {
class DialogInstructionFinder;
}

class DialogInstructionFinder : public QDialog
{
    Q_OBJECT

public:
    explicit DialogInstructionFinder(QWidget *parent = 0);
    ~DialogInstructionFinder();

private:
    void assemble(QStringList instructions);
    void do_find();

private slots:
    void on_checkBoxAnyRegion_stateChanged(int status);

    void on_lineEditRegion_textEdited(const QString &arg1);

    void on_pushButtonReset_clicked();

    void on_pushButtonFind_clicked();

    void on_listWidgetResults_itemDoubleClicked(QListWidgetItem *item);

private:
    Ui::DialogInstructionFinder *ui;

private:
    QByteArray *assembly_bytes_;
    edb::address_t address_;
};

#endif // DIALOGINSTRUCTIONFINDER_H
