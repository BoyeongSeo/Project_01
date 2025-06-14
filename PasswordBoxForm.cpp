#include <vcl.h>
#include <windows.h>
#pragma hdrstop

#include "PasswordBoxForm.h"

#pragma package(smart_init)
#pragma resource "*.dfm"

TPasswordBoxForm *PasswordBoxForm;

__fastcall TPasswordBoxForm::TPasswordBoxForm(TComponent* Owner)
    : TForm(Owner)
{
    // Password masking
    PasswordEdit->PasswordChar = '*';
    Image1 = new TImage(this);
    Image1->Parent = this;
    Image1->Left = 20;
    Image1->Top = 50;
    Image1->Width = ClientWidth - 40;
    Image1->Height = ClientWidth - 40;
    Image1->Stretch = true;
    Image1->Picture->LoadFromFile("aim_high.bmp");
}

String TPasswordBoxForm::GetUsername()
{
    return UsernameEdit->Text;
}

String TPasswordBoxForm::GetPassword()
{
    return PasswordEdit->Text;
}

void TPasswordBoxForm::SetFlightNum(String flight)
{
    FlightNum->Caption = flight;
}

void TPasswordBoxForm::SetEmail(String email)
{
	EmailLabel->Caption = "Email: " + email;
}

String TPasswordBoxForm::GetAuthCode(void)
{
	return AuthCode;
}

void TPasswordBoxForm::SetAuthCode(String code)
{
	AuthCode = code;
}

void __fastcall TPasswordBoxForm::LoginButtonClick(TObject *Sender)
{
	String username = GetUsername();
    String password = GetPassword();
	String code;

	String email;
	if (AuthenticateUser(username, password, email)) {
		SetEmail(maskEmail(email));
		code = MFAuthentication(email);
		SetAuthCode(code);
		ShowMessage("User Verification Success.");
		UserVerified = true;
	} else {
		ShowMessage("User Verification Failed. Try again.");
    }
}

void __fastcall TPasswordBoxForm::OKButtonClick(TObject *Sender)
{
    String passcode = UserPasscodeEdit->Text;

	if (!UserVerified) {
		   ShowMessage("Please authenticate user first.");
		   return;
	}

	if (!isValidPasscode(passcode)) {
			ShowMessage("Invalid passcode. Input 6-digit");
			return;
	}

	if (passcode == GetAuthCode()) {
        ModalResult = mrOk;  // final success
        UserAuthorized = true;
	} else {
		ShowMessage("Invalid passcode. Try again.");
		return;
	}
}
void __fastcall TPasswordBoxForm::FormClose(TObject *Sender, TCloseAction &Action)
{
    if (!UserAuthorized) {
        ExitProcess(-1);
    }
}
//---------------------------------------------------------------------------
