object PasswordBoxForm: TPasswordBoxForm
  Left = 300
  Top = 300
  BorderStyle = bsDialog
  Caption = 'Password Required'
  ClientHeight = 620
  ClientWidth = 300
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'Tahoma'
  Font.Style = []
  Position = poScreenCenter
  OnClose = FormClose
  TextHeight = 13
  object Label0: TLabel
    Left = 11
    Top = 8
    Width = 274
    Height = 23
    Caption = 'Protected Flight Information'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -19
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object UsernameLabel: TLabel
    Left = 16
    Top = 320
    Width = 52
    Height = 13
    Caption = 'Username:'
  end
  object Label1: TLabel
    Left = 16
    Top = 370
    Width = 79
    Height = 13
    Caption = 'Enter password:'
  end
  object Label2: TLabel
    Left = 16
    Top = 468
    Width = 187
    Height = 18
    Caption = 'Input 2-Factor Auth Code'
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -15
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object EmailLabel: TLabel
    Left = 16
    Top = 501
    Width = 41
    Height = 16
    Caption = 'Email: '
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -13
    Font.Name = 'Tahoma'
    Font.Style = [fsBold]
    ParentFont = False
  end
  object UsernameEdit: TEdit
    Left = 16
    Top = 340
    Width = 265
    Height = 21
    TabOrder = 0
  end
  object PasswordEdit: TEdit
    Left = 16
    Top = 390
    Width = 265
    Height = 21
    PasswordChar = '*'
    TabOrder = 1
  end
  object LoginButton: TButton
    Left = 124
    Top = 417
    Width = 75
    Height = 25
    Caption = 'Send'
    TabOrder = 2
    OnClick = LoginButtonClick
  end
  object CancelButton: TButton
    Left = 205
    Top = 417
    Width = 75
    Height = 25
    Caption = 'Cancel'
    ModalResult = 2
    TabOrder = 3
  end
  object UserPasscodeEdit: TEdit
    Left = 16
    Top = 523
    Width = 265
    Height = 21
    TabOrder = 4
  end
  object OKButton: TButton
    Left = 206
    Top = 550
    Width = 75
    Height = 25
    Caption = 'OK'
    TabOrder = 5
    OnClick = OKButtonClick
  end
end
