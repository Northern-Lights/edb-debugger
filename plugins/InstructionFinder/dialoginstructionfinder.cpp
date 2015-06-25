#include "dialoginstructionfinder.h"
#include "ui_dialoginstructionfinder.h"

#include "edb.h"
#include "IDebugger.h"
#include "string_hash.h"
#include "ByteShiftArray.h"
#include "MemoryRegions.h"

#include <QTemporaryFile>
#include <QDir>
#include <QProcess>
#include <QDebug>
#include <QRegExp>
#include <QFile>
#include <QFileInfo>
#include <QMessageBox>
#include <QSettings>

#ifdef Q_OS_UNIX
#include <sys/types.h>
#include <unistd.h>
#endif

DialogInstructionFinder::DialogInstructionFinder(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DialogInstructionFinder)
{
    ui->setupUi(this);
    assembly_bytes_ = new QByteArray();
    address_ = 0;
}

DialogInstructionFinder::~DialogInstructionFinder()
{
    delete ui;
    delete assembly_bytes_;
}

void DialogInstructionFinder::on_checkBoxAnyRegion_stateChanged(int status)
{
    if (status == Qt::Checked) {
        ui->lineEditRegion->clear(); }
}

void DialogInstructionFinder::on_lineEditRegion_textEdited(const QString &arg1)
{
    Q_UNUSED(arg1);

    QCheckBox *c = ui->checkBoxAnyRegion;
    if (c->isChecked()) {
        c->toggle();
    }
}

/**
 * @brief DialogInstructionFinder::on_pushButtonReset_clicked
 * Clears all input and output.
 */
void DialogInstructionFinder::on_pushButtonReset_clicked()
{
    ui->lineEditRegion->clear();
    ui->textEditInstructions->clear();
    ui->listWidgetResults->clear();

    QCheckBox *c = ui->checkBoxAnyRegion;
    if(c->isChecked()) {
        c->toggle(); }
}

/**
 * @brief DialogInstructionFinder::on_pushButtonFind_clicked
 * Initiates the assemble + search.
 * For now, just copies the text from the editor to here.
 */
void DialogInstructionFinder::on_pushButtonFind_clicked()
{
    //Get the instruction text and results list widget
    QString instructions = ui->textEditInstructions->toPlainText();
    QListWidget *results = ui->listWidgetResults;

    //Clear any old results
    results->clear();

    //Get the address, if any
    if (!ui->checkBoxAnyRegion->isChecked())
    {
        const QString text = ui->lineEditRegion->displayText();

        bool ok;
        edb::address_t addr = text.toLong(&ok, 0);     //TODO possible portability issue
        if (ok) {
            address_ = addr;
        }
    }

    //Get each instruction, put into a list
    QStringList instruction_list = instructions.split(QString("\n"));

    //Assemble the instructions, then search for the bytes.
    assemble(instruction_list);
    do_find();
//    QString s = QString().number(assembly_bytes_->size(), 10);
//    ui->listWidgetResults->addItem(s);
}

void DialogInstructionFinder::assemble(QStringList instructions)
{
    //Clear the byte array
    assembly_bytes_->clear();

    static const QString mnemonic_regex   = "([a-z][a-z0-9]*)";
    static const QString register_regex   = "((?:(?:e|r)?(?:ax|bx|cx|dx|bp|sp|si|di|ip))|(?:[abcd](?:l|h))|(?:sp|bp|si|di)l|(?:[cdefgs]s)|(?:x?mm[0-7])|r(?:8|9|(?:1[0-5]))[dwb]?)";
    static const QString constant_regex   = "((?:0[0-7]*)|(?:0x[0-9a-f]+)|(?:[1-9][0-9]*))";

    static const QString pointer_regex    = "(?:(t?byte|(?:xmm|[qdf]?)word)(?:\\s+ptr)?)?";
    static const QString segment_regex    = "([csdefg]s)";
    static const QString expression_regex = QString("(%1\\s*(?:\\s+%2\\s*:\\s*)?\\[(\\s*(?:(?:%3(?:\\s*\\+\\s*%3(?:\\s*\\*\\s*%4)?)?(?:\\s*\\+\\s*%4)?)|(?:(?:%3(?:\\s*\\*\\s*%4)?)(?:\\s*\\+\\s*%4)?)|(?:%4)\\s*))\\])").arg(pointer_regex, segment_regex, register_regex, constant_regex);

    static const QString operand_regex    = QString("((?:%1)|(?:%2)|(?:%3))").arg(register_regex, constant_regex, expression_regex);

    static const QString assembly_regex   = QString("%1(?:\\s+%2\\s*(?:\\s*,\\s*%2\\s*(?:\\s*,\\s*%2\\s*)?)?)?").arg(mnemonic_regex, operand_regex);

// [                 OFFSET]
// [     INDEX             ]
// [     INDEX      +OFFSET]
// [     INDEX*SCALE       ]
// [     INDEX*SCALE+OFFSET]
// [BASE                   ]
// [BASE            +OFFSET]
// [BASE+INDEX             ]
// [BASE+INDEX      +OFFSET]
// [BASE+INDEX*SCALE       ]
// [BASE+INDEX*SCALE+OFFSET]
// -------------------------
// [((BASE(\+INDEX(\*SCALE)?)?(\+OFFSET)?)|((INDEX(\*SCALE)?)(\+OFFSET)?)|(OFFSET))]

/***************************START SOME WORK HERE*******************************************/

    Q_FOREACH(QString instruction, instructions) {
        QString assembly = instruction.trimmed();

//	const QString assembly = ui->assembly->currentText().trimmed();
    QRegExp regex(assembly_regex, Qt::CaseInsensitive, QRegExp::RegExp2);

    if(regex.exactMatch(assembly)) {
        const QStringList list = regex.capturedTexts();


/*
[0]  -> whole match
[1]  -> mnemonic

[2]  -> whole operand 1
[3]  -> operand 1 (REGISTER)
[4]  -> operand 1 (IMMEDIATE)
[5]  -> operand 1 (EXPRESSION)
[6]  -> operand 1 pointer (EXPRESSION)
[7]  -> operand 1 segment (EXPRESSION)
[8]  -> operand 1 internal expression (EXPRESSION)
[9]  -> operand 1 base (EXPRESSION)
[10] -> operand 1 index (EXPRESSION)
[11] -> operand 1 scale (EXPRESSION)
[12] -> operand 1 displacement (EXPRESSION)
[13] -> operand 1 index (EXPRESSION) (version 2)
[14] -> operand 1 scale (EXPRESSION) (version 2)
[15] -> operand 1 displacement (EXPRESSION) (version 2)
[16] -> operand 1 displacement (EXPRESSION) (version 3)

[17] -> whole operand 2
[18] -> operand 2 (REGISTER)
[19] -> operand 2 (IMMEDIATE)
[20] -> operand 2 (EXPRESSION)
[21] -> operand 2 pointer (EXPRESSION)
[22] -> operand 2 segment (EXPRESSION)
[23] -> operand 2 internal expression (EXPRESSION)
[24] -> operand 2 base (EXPRESSION)
[25] -> operand 2 index (EXPRESSION)
[26] -> operand 2 scale (EXPRESSION)
[27] -> operand 2 displacement (EXPRESSION)
[28] -> operand 2 index (EXPRESSION) (version 2)
[29] -> operand 2 scale (EXPRESSION) (version 2)
[30] -> operand 2 displacement (EXPRESSION) (version 2)
[31] -> operand 2 displacement (EXPRESSION) (version 3)

[32] -> whole operand 3
[33] -> operand 3 (REGISTER)
[34] -> operand 3 (IMMEDIATE)
[35] -> operand 3 (EXPRESSION)
[36] -> operand 3 pointer (EXPRESSION)
[37] -> operand 3 segment (EXPRESSION)
[38] -> operand 3 internal expression (EXPRESSION)
[39] -> operand 3 base (EXPRESSION)
[40] -> operand 3 index (EXPRESSION)
[41] -> operand 3 scale (EXPRESSION)
[42] -> operand 3 displacement (EXPRESSION)
[43] -> operand 3 index (EXPRESSION) (version 2)
[44] -> operand 3 scale (EXPRESSION) (version 2)
[45] -> operand 3 displacement (EXPRESSION) (version 2)
[46] -> operand 3 displacement (EXPRESSION) (version 3)
*/

        int operand_count = 0;
        if(!list[2].isEmpty()) {
            ++operand_count;
        }

        if(!list[17].isEmpty()) {
            ++operand_count;
        }

        if(!list[32].isEmpty()) {
            ++operand_count;
        }

        QStringList operands;

        for(int i = 0; i < operand_count; ++i) {

            int offset = 15 * i;

            if(!list[3 + offset].isEmpty()) {
                operands << list[3 + offset];
            } else if(!list[4 + offset].isEmpty()) {
                operands << list[4 + offset];
            } else if(!list[5 + offset].isEmpty()) {
                if(!list[7 + offset].isEmpty()) {
                    operands << QString("%1 [%2:%3]").arg(list[6 + offset], list[7 + offset], list[8 + offset]);
                } else {
                    operands << QString("%1 [%2]").arg(list[6 + offset], list[8 + offset]);
                }
            }
        }

        const QString nasm_syntax = list[1] + ' ' + operands.join(",");

        QTemporaryFile source_file(QString("%1/edb_asm_temp_%2_XXXXXX.asm").arg(QDir::tempPath()).arg(getpid()));
        if(!source_file.open()) {
            QMessageBox::critical(this, tr("Error Creating File"), tr("Failed to create temporary source file."));
            return;
        }

        QTemporaryFile output_file(QString("%1/edb_asm_temp_%2_XXXXXX.bin").arg(QDir::tempPath()).arg(getpid()));
        if(!output_file.open()) {
            QMessageBox::critical(this, tr("Error Creating File"), tr("Failed to create temporary object file."));
            return;
        }

        QSettings settings;
        const QString assembler = settings.value("Assembler/helper_application", "/usr/bin/yasm").toString();
        const QFile file(assembler);
        if(assembler.isEmpty() || !file.exists()) {
            QMessageBox::warning(this, tr("Couldn't Find Assembler"), tr("Failed to locate your assembler, please specify one in the options."));
            return;
        }

        const QFileInfo info(assembler);

        QProcess process;
        QStringList arguments;
        QString program(assembler);

        if(info.fileName() == "yasm") {

            switch(edb::v1::debugger_core->cpu_type()) {
            case edb::string_hash<'x', '8', '6'>::value:
                source_file.write("[BITS 32]\n");
                break;
            case edb::string_hash<'x', '8', '6', '-', '6', '4'>::value:
                source_file.write("[BITS 64]\n");
                break;
            default:
                Q_ASSERT(0);
            }

//            source_file.write(QString("[SECTION .text vstart=0x%1 valign=1]\n\n").arg(edb::v1::format_pointer(address_)).toLatin1());
            source_file.write(nasm_syntax.toLatin1());
            source_file.write("\n");
            source_file.close();

            arguments << "-o" << output_file.fileName();
            arguments << "-f" << "bin";
            arguments << source_file.fileName();
        } else if(info.fileName() == "nasm") {

            switch(edb::v1::debugger_core->cpu_type()) {
            case edb::string_hash<'x', '8', '6'>::value:
                source_file.write("[BITS 32]\n");
                break;
            case edb::string_hash<'x', '8', '6', '-', '6', '4'>::value:
                source_file.write("[BITS 64]\n");
                break;
            default:
                Q_ASSERT(0);
            }

//            source_file.write(QString("ORG 0x%1\n\n").arg(edb::v1::format_pointer(address_)).toLatin1());
            source_file.write(nasm_syntax.toLatin1());
            source_file.write("\n");
            source_file.close();


            arguments << "-o" << output_file.fileName();
            arguments << "-f" << "bin";
            arguments << source_file.fileName();
        }

        process.start(program, arguments);

        if(process.waitForFinished()) {

            const int exit_code = process.exitCode();

            if(exit_code != 0) {
                QMessageBox::warning(this, tr("Error In Code"), process.readAllStandardError());
            } else {
                QByteArray bytes = output_file.readAll();
                assembly_bytes_->append(bytes);

//				if(bytes.size() <= instruction_size_) {
//					if(ui->fillWithNOPs->isChecked()) {
//						// TODO: get system independent nop-code
//						edb::v1::modify_bytes(address_, instruction_size_, bytes, 0x90);
//					} else {
//						edb::v1::modify_bytes(address_, instruction_size_, bytes, 0x00);
//					}
//				} else {
//					if(ui->keepSize->isChecked()) {
//						QMessageBox::warning(this, tr("Error In Code"), tr("New instruction is too big to fit."));
//					} else {
//						edb::v1::modify_bytes(address_, bytes.size(), bytes, 0x00);
//					}
//				}
            }
        }
    } else {
        QMessageBox::warning(this, tr("Error In Code"), tr("Failed to assembly the given assemble code."));
    }
    }
    return;
}

void DialogInstructionFinder::do_find()
{
    const int sz = assembly_bytes_->size();

    if (sz != 0) {
        ByteShiftArray bsa(sz);

        //Get the region(s).
        edb::v1::memory_regions().sync();
        QList<IRegion::pointer> regions;

        //If we're checking any region, get all regions.
        if (ui->checkBoxAnyRegion->isChecked()) {
            regions = edb::v1::memory_regions().regions();
        }
        //Otherwise, if we have an address in the lineEdit box, find its region.
        else if (address_) {
            QList<IRegion::pointer> list;

            //Make sure we get a valid pointer, otherwise just return and do nothing.
            if(IRegion::pointer p = edb::v1::memory_regions().find_region(address_)) {
                list.append(p);
                regions = list;
            } else return;
        } else {
            return;     //TODO "Error"
        }

        const edb::address_t page_size = edb::v1::debugger_core->page_size();

        int i = 0;
        Q_FOREACH(const IRegion::pointer &region, regions)
        {
            bsa.clear();

            const size_t page_count = region->size() / page_size;
            const QVector<quint8> pages = edb::v1::read_pages(region->start(), page_count);

            if (!pages.isEmpty())
            {
                const quint8 *p = &pages[0];
                const quint8 *const pages_end = &pages[0] + region->size();

                QString temp;
                while (p != pages_end)
                {
                    bsa << *p;

                    if(std::memcmp(bsa.data(), assembly_bytes_->constData(), sz) == 0) {
                        const edb::address_t addr = (p - &pages[0] + region->start()) - sz + 1;
//                        const edb::address_t align = 1 << (ui->cmbAlignment->currentIndex() + 1);

                        QListWidgetItem *item = new QListWidgetItem(edb::v1::format_pointer(addr));
                        item->setData(Qt::UserRole, addr);
                        ui->listWidgetResults->addItem(item);
                    }
                    ++p;
                }
            }
            ++i;
        }
    }
}

void DialogInstructionFinder::on_listWidgetResults_itemDoubleClicked(QListWidgetItem *item)
{
    edb::address_t addr = item->data(Qt::UserRole).toULongLong();
    edb::v1::jump_to_address(addr);
}
