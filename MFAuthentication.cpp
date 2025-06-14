#include <IdSMTP.hpp>
#include <IdMessage.hpp>
#include <IdSSLOpenSSL.hpp>
#include <IdHTTP.hpp>
#include <IdSSLOpenSSL.hpp>
#include <System.JSON.hpp>
#include <System.Character.hpp>
#include <System.IOUtils.hpp> // for TPath
#include "secure_logger.h"

using namespace std;

extern SecureLogger logger;

bool AuthenticateUser(String username, String password, String &userEmail)
{
    try {
        std::unique_ptr<TIdHTTP> http(new TIdHTTP(nullptr));
        std::unique_ptr<TIdSSLIOHandlerSocketOpenSSL> sslHandler(new TIdSSLIOHandlerSocketOpenSSL(nullptr));
		std::unique_ptr<TStringStream> requestBody(new TStringStream("", TEncoding::UTF8, false));
        std::unique_ptr<TStringStream> responseBody(new TStringStream("", TEncoding::UTF8, false));

        // Configure SSL handler for TLS 1.2
        sslHandler->SSLOptions->Method = sslvTLSv1_2;
        sslHandler->SSLOptions->SSLVersions.Clear(); // Clear existing versions
        sslHandler->SSLOptions->SSLVersions << sslvTLSv1_2; // Include TLS 1.2
        sslHandler->SSLOptions->VerifyMode = TIdSSLVerifyModeSet() << sslvrfPeer; // "must verify peer" setting

        // Set paths for certificates and keys
        String certPath = TPath::Combine(TPath::GetDirectoryName(Application->ExeName), "cert");
        sslHandler->SSLOptions->RootCertFile = TPath::Combine(certPath, "ca.crt");
        // sslHandler->SSLOptions->CertFile     = TPath::Combine(certPath, "client.crt");
        // sslHandler->SSLOptions->KeyFile      = TPath::Combine(certPath, "client.key");

        http->IOHandler = sslHandler.get();
        // sslHandler->SSLOptions->VerifyDepth = 2;

        // Create JSON
        TJSONObject *json = new TJSONObject();
        json->AddPair("username", username);
        json->AddPair("password", password);
        requestBody->WriteString(json->ToString());
        delete json;

		// Set Content-Type
        http->Request->ContentType = "application/json";

		// POST
        http->Post("https://127.0.0.1/auth", requestBody.get(), responseBody.get());

        //parse response
		responseBody->Position = 0;
        String responseText = responseBody->DataString;

        std::unique_ptr<TJSONObject> resJson((TJSONObject *)TJSONObject::ParseJSONValue(responseText));
        if (resJson && resJson->GetValue("status")->Value() == "success") {
            TJSONValue* emailVal = resJson->GetValue("email");
            if (emailVal && dynamic_cast<TJSONString*>(emailVal)) {
                userEmail = static_cast<TJSONString*>(emailVal)->Value();
				//printf("User Email: %s\n", AnsiString(userEmail).c_str());
			}
			TJSONValue* userId = resJson->GetValue("user_id");
			String aesKey = userId->Value();  // UnicodeString (== System::String)
			//printf("User ID: %s\n", AnsiString(userIdStr).c_str());

			////// Validate and set AES key and set it
			if(is_valid_aes_key_string(aesKey)){
				BYTE tmp_aesKey[KEY_SIZE];
				if(hex_string_to_aes_key(aesKey, tmp_aesKey)) {
					set_aes_key(tmp_aesKey, KEY_SIZE);
					logger.info("AES key obtained successfully from server.");
				} else {
					ShowMessage("Invalid AES key format received from server.");
					ExitProcess(-1);
					// return false;
				}
			} else {
				ShowMessage("Invalid AES key format received from server.");
				ExitProcess(-1);
				// return false;
			}
            return true;
        }
    }
    catch (const Exception &e) {
        ShowMessage("Auth server error " + e.ClassName() + "\nMessage: " + e.Message);
    }

    return false;
}

bool isValidPasscode(const String& passcode) {
    if (passcode.Length() != 6)
        return false;

	for (int i = 1; i <= passcode.Length(); ++i) {
		if (!System::Character::IsDigit(passcode[i]))
            return false;
    }

    return true;
}

static String generate_verification_code() {
	srand(time(nullptr));
	int code = rand() % 900000 + 100000; // 6dgit code
	return String(code);
}

String maskEmail(String email) {
    int atPos = email.Pos("@");  // 1-based index
	if (atPos == 0 || atPos <= 3) {
		return email;
    }

	String prefix = email.SubString(1, 3);
	int maskLength = atPos - 4;
	String maskedPart = String().StringOfChar('*', maskLength);
	String domain = email.SubString(atPos, email.Length() - atPos + 1);

    return prefix + maskedPart + domain;
}

String MFAuthentication(String email)
{
	 // declare smart pointer
	std::unique_ptr<TIdSMTP> smtp(new TIdSMTP(nullptr));
	std::unique_ptr<TIdMessage> msg(new TIdMessage(nullptr));
	std::unique_ptr<TIdSSLIOHandlerSocketOpenSSL> ssl(new TIdSSLIOHandlerSocketOpenSSL(nullptr));
	String code = generate_verification_code();
	String bodytext = "Your OTP is: " + code;

	// setting SSL
	ssl->SSLOptions->Method = sslvTLSv1_2;
	ssl->SSLOptions->Mode = sslmUnassigned;

	// setting SMTP for Gmail
	smtp->Host = "smtp.gmail.com";
	smtp->Port = 587;
	smtp->Username = "stellarmatia@gmail.com";
	smtp->Password = "cozganqgqqpixdlr";
	smtp->IOHandler = ssl.get();
	smtp->UseTLS = utUseExplicitTLS;

	// make Message
	msg->From->Address = "FAS Admin";
	msg->Recipients->Add()->Address = email;
	msg->Subject = "Flight Agent System 2-Factor Authentication Code";
	msg->Body->Text = String(bodytext.c_str());

	// sent e-mail
	try {
		smtp->Connect();
		smtp->Send(msg.get());
		smtp->Disconnect();
		//ShowMessage("Email sent successfully! - " + String(code.c_str()));
	} catch (const Exception& e) {
		ShowMessage("Failed to send email: " + e.ClassName() + ": "+ e.Message);
	}
	return code;
}
