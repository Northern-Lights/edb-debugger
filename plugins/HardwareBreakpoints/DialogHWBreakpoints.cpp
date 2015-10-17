/*
Copyright (C) 2006 - 2015 Evan Teran
                          evan.teran@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "DialogHWBreakpoints.h"
#include "edb.h"
#include "IDebugger.h"
#include "State.h"

#include "ui_DialogHWBreakpoints.h"

namespace HardwareBreakpoints {

//------------------------------------------------------------------------------
// Name: DialogHWBreakpoints
// Desc:
//------------------------------------------------------------------------------
DialogHWBreakpoints::DialogHWBreakpoints(QWidget *parent) : QDialog(parent), ui(new Ui::DialogHWBreakpoints) {
	ui->setupUi(this);

	connect(ui->cmbType1, SIGNAL(currentIndexChanged(int)), this, SLOT(type1IndexChanged(int)));
	connect(ui->cmbType2, SIGNAL(currentIndexChanged(int)), this, SLOT(type2IndexChanged(int)));
	connect(ui->cmbType3, SIGNAL(currentIndexChanged(int)), this, SLOT(type3IndexChanged(int)));
	connect(ui->cmbType4, SIGNAL(currentIndexChanged(int)), this, SLOT(type4IndexChanged(int)));
}

//------------------------------------------------------------------------------
// Name: ~DialogHWBreakpoints
// Desc:
//------------------------------------------------------------------------------
DialogHWBreakpoints::~DialogHWBreakpoints() {
	delete ui;
}

//------------------------------------------------------------------------------
// Name: type1IndexChanged
// Desc:
//------------------------------------------------------------------------------
void DialogHWBreakpoints::type1IndexChanged(int index) {
	ui->cmbSize1->setEnabled(index != 0);
}

//------------------------------------------------------------------------------
// Name: type2IndexChanged
// Desc:
//------------------------------------------------------------------------------
void DialogHWBreakpoints::type2IndexChanged(int index) {
	ui->cmbSize2->setEnabled(index != 0);
}

//------------------------------------------------------------------------------
// Name: type3IndexChanged
// Desc:
//------------------------------------------------------------------------------
void DialogHWBreakpoints::type3IndexChanged(int index) {
	ui->cmbSize3->setEnabled(index != 0);
}

//------------------------------------------------------------------------------
// Name: type4IndexChanged
// Desc:
//------------------------------------------------------------------------------
void DialogHWBreakpoints::type4IndexChanged(int index) {
	ui->cmbSize4->setEnabled(index != 0);
}

//------------------------------------------------------------------------------
// Name: showEvent
// Desc:
//------------------------------------------------------------------------------
void DialogHWBreakpoints::showEvent(QShowEvent *event) {
	Q_UNUSED(event);

	State state;
	edb::v1::debugger_core->get_state(&state);

	const bool bp1_enabled = (state.debug_register(7) & 0x00000001) != 0;
	const bool bp2_enabled = (state.debug_register(7) & 0x00000004) != 0;
	const bool bp3_enabled = (state.debug_register(7) & 0x00000010) != 0;
	const bool bp4_enabled = (state.debug_register(7) & 0x00000040) != 0;

	ui->chkBP1->setChecked(bp1_enabled);
	ui->chkBP2->setChecked(bp2_enabled);
	ui->chkBP3->setChecked(bp3_enabled);
	ui->chkBP4->setChecked(bp4_enabled);

	if(bp1_enabled) {
		ui->txtBP1->setText(state.debug_register(0).toPointerString());
	}

	if(bp2_enabled) {
		ui->txtBP2->setText(state.debug_register(1).toPointerString());
	}

	if(bp3_enabled) {
		ui->txtBP3->setText(state.debug_register(2).toPointerString());
	}

	if(bp4_enabled) {
		ui->txtBP4->setText(state.debug_register(3).toPointerString());
	}
}

}
