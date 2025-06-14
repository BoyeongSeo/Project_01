#ifndef PasswordBoxFormH
#define PasswordBoxFormH

#include <Classes.hpp>
#include <Controls.hpp>
#include <StdCtrls.hpp>
#include <Forms.hpp>

//---------------------------------------------------------------------------

extern bool AuthenticateUser(String username, String password, String &userEmail);
extern String MFAuthentication(String email);
extern String maskEmail(String email);
extern bool isValidPasscode(const String& passcode);

class TPasswordBoxForm : public TForm
{
__published:
    TLabel *Label0;
    TLabel *Label1;
    TLabel *Label2;
    TLabel *FlightNum;
    TLabel *UsernameLabel;
    TLabel *EmailLabel;
    TEdit *UsernameEdit;
    TEdit *PasswordEdit;
    TEdit *UserPasscodeEdit;
    TButton *LoginButton;
    TButton *CancelButton;
	TButton *OKButton;

    TImage *Image1;
    void __fastcall LoginButtonClick(TObject *Sender);
	void __fastcall OKButtonClick(TObject *Sender);
	void __fastcall FormClose(TObject *Sender, TCloseAction &Action);
private:
	String AuthCode;
	bool UserVerified = false;
    bool UserAuthorized = false;

public:
    __fastcall TPasswordBoxForm(TComponent* Owner);
    String GetUsername();
    String GetPassword();
    void SetFlightNum(String flight);
	void SetEmail(String email);
	String GetAuthCode(void);
	void SetAuthCode(String code);
};

#endif
