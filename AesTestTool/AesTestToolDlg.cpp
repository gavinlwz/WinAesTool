
// AesTestToolDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "AesTestTool.h"
#include "AesTestToolDlg.h"
#include "afxdialogex.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#include "AesWrapper.h"


// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CAesTestToolDlg 对话框



CAesTestToolDlg::CAesTestToolDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_AESTESTTOOL_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CAesTestToolDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_PLAINTEXT, editPlaintext);
	DDX_Control(pDX, IDC_COMBO_AES, mCboxAes);
	DDX_Control(pDX, IDC_COMBO_KEY, mCboxKey);
	DDX_Control(pDX, IDC_COMBO_PADD, mCboxPadd);
	DDX_Control(pDX, IDC_EDIT_KEY, mEditKey);
	DDX_Control(pDX, IDC_EDIT2, mEditIv);
	DDX_Control(pDX, IDC_EDIT3, mEditInputData);
	DDX_Control(pDX, IDC_EDIT4, mEditMac);
	DDX_Control(pDX, IDC_CHECK_MAC, mCheckMac);
	DDX_Control(pDX, IDC_EDIT_MAC_STATUS, mMacStatus);
}

BEGIN_MESSAGE_MAP(CAesTestToolDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON_ENCRYPT, &CAesTestToolDlg::OnBnClickedButtonEncrypt)
	ON_BN_CLICKED(IDC_BUTTON_DECRYPT, &CAesTestToolDlg::OnBnClickedButtonDecrypt)
END_MESSAGE_MAP()


// CAesTestToolDlg 消息处理程序

BOOL CAesTestToolDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	SetWindowText("AES Tool");
	mCboxAes.AddString("CBC");
	mCboxAes.AddString("ECB");
	mCboxAes.AddString("CTR");
	mCboxAes.AddString("OFB");
	mCboxAes.AddString("CFB");
	mCboxAes.SetCurSel(0);

	mCboxKey.AddString("128bits");
	mCboxKey.AddString("192bits");
	mCboxKey.AddString("256bits");
	mCboxKey.SetCurSel(0);

	mCboxPadd.AddString("Zero");
	mCboxPadd.AddString("PKCS7");
	mCboxPadd.SetCurSel(0);

	LoadInputData();
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CAesTestToolDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CAesTestToolDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CAesTestToolDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

int CAesTestToolDlg::hexstr2bytes(CString str, uint8_t* ouput)
{
	char* p = str.GetBuffer();
	int len = str.GetLength();
	uint8_t val_h;
	uint8_t val_l;
	char c;
	int j = 0;
	int ret = 0;
	for (int i = 0; i < len; )
	{
		c = p[i];
		if (c >= '0' && c <= '9')
		{
			val_h = c - '0';
		}
		else  if (c >= 'A' && c <= 'F')
		{
			val_h = 10 + c - 'A';
		}
		else  if (c >= 'a' && c <= 'f')
		{
			val_h = 10 + c - 'a';
		}
		else {
			val_h = 0;
		}

		c = p[i + 1];
		if (c >= '0' && c <= '9')
		{
			val_l = c - '0';
		}
		else  if (c >= 'A' && c <= 'F')
		{
			val_l = 10 + c - 'A';
		}
		else  if (c >= 'a' && c <= 'f')
		{
			val_l = 10 + c - 'a';
		}
		else {
			val_l = 0;
		}
		j = i / 2;
		ouput[j] = (val_h << 4) + val_l;
		i += 2;
		ret++;
	}
	return ret;
}

void CAesTestToolDlg::LoadInputData()
{
	CString aes;
	::GetPrivateProfileString("input", "AES", "", aes.GetBuffer(33), 33, ".//setting.ini");
	int cnt = mCboxAes.GetCount();
	CString aesName;
	for (int i = 0; i < cnt; i++)
	{
		mCboxAes.GetLBText(i, aesName);
		if (aes == aesName)
		{
			mCboxAes.SetCurSel(i);
			break;
		}
	}

	CString key;
	::GetPrivateProfileString("input", "KEY", "", key.GetBuffer(33), 33, ".//setting.ini");
	mEditKey.SetWindowTextA(key);

	CString keySize;
	::GetPrivateProfileString("input", "KeySize", "", keySize.GetBuffer(16), 16, ".//setting.ini");
	if (-1 != keySize.Find("128"))
	{
		mCboxKey.SetCurSel(0);
	}
	else if (-1 != keySize.Find("192"))
	{
		mCboxKey.SetCurSel(1);
	}
	else if (-1 != keySize.Find("256"))
	{
		mCboxKey.SetCurSel(2);
	}

	CString nonceCount;
	::GetPrivateProfileString("input", "IV", "", nonceCount.GetBuffer(33), 33, ".//setting.ini");
	mEditIv.SetWindowTextA(nonceCount);

	int isCheckTag = ::GetPrivateProfileInt("input", "CheckMac", 0, ".//setting.ini");
	mCheckMac.SetCheck(isCheckTag);
	if (isCheckTag)
	{
		CString tag;
		::GetPrivateProfileString("input", "MAC", "", tag.GetBuffer(17), 17, ".//setting.ini");
		mEditMac.SetWindowTextA(tag);
	}

	CString ciphertext;
	::GetPrivateProfileString("input", "DATA", "", ciphertext.GetBuffer(63), 63, ".//setting.ini");
	mEditInputData.SetWindowTextA(ciphertext);
}



void CAesTestToolDlg::OnBnClickedButtonEncrypt()
{
	size_t len;
	int key_size = 128;

	CString aesStr;
	mCboxAes.GetWindowTextA(aesStr);
	::WritePrivateProfileString("input", "AES", aesStr, ".//setting.ini");

	CString keyStr;
	mEditKey.GetWindowTextA(keyStr);
	keyStr.Trim();
	len = keyStr.GetLength();
	if ((len != 32) && (len != 64) && (len != 48))
	{
		AfxMessageBox("Key is illegal");
		return;
	}
	if (keyStr.SpanIncluding(_T("0123456789abcdefABCDEF")) != keyStr)
	{
		AfxMessageBox("Key is illegal hex string");
		return;
	}
	::WritePrivateProfileString("input", "KEY", keyStr, ".//setting.ini");

	int cur_sel = mCboxKey.GetCurSel();
	if (0 == cur_sel)
	{
		key_size = 128;
	}
	else if (1 == cur_sel)
	{
		key_size = 192;
	}
	else if (2 == cur_sel)
	{
		key_size = 256;
	}
	CString keySizeStr;
	keySizeStr.Format("%dbits", key_size);
	::WritePrivateProfileString("input", "KeySize", keySizeStr, ".//setting.ini");

	CString ivStr;
	mEditIv.GetWindowTextA(ivStr);
	ivStr.Trim();
	len = ivStr.GetLength();
	if ((len & 1) || (0 == len))
	{
		AfxMessageBox("IV is illegal");
		return;
	}
	if (ivStr.SpanIncluding(_T("0123456789abcdefABCDEF")) != ivStr)
	{
		AfxMessageBox("IV is illegal hex string");
		return;
	}
	::WritePrivateProfileString("input", "IV", ivStr, ".//setting.ini");

	int isCheckMac = mCheckMac.GetCheck();
	CString isCheckMacStr;
	isCheckMacStr.Format("%d", isCheckMac);
	::WritePrivateProfileString("input", "CheckMac", isCheckMacStr, ".//setting.ini");
	CString macStr;
	if (isCheckMac)
	{
		mEditMac.GetWindowTextA(macStr);
		macStr.Trim();
		len = macStr.GetLength();
		if ( 0 == len || (1 == (len & 1)) || len > 32)
		{
			AfxMessageBox("MAC is illegal");
			return;
		}
		if (macStr.SpanIncluding(_T("0123456789abcdefABCDEF")) != macStr)
		{
			AfxMessageBox("MAC is illegal hex string");
			return;
		}
		::WritePrivateProfileString("input", "MAC", macStr, ".//setting.ini");
	}

	CString dataStr;
	mEditInputData.GetWindowTextA(dataStr);
	dataStr.Trim();
	len = dataStr.GetLength();
	if (0 == len || (1 == (len & 1)))
	{
		AfxMessageBox("Input Data is illegal");
		return;
	}
	if (dataStr.SpanIncluding(_T("0123456789abcdefABCDEF")) != dataStr)
	{
		AfxMessageBox("Input Data is illegal hex string");
		return;
	}
	::WritePrivateProfileString("input", "DATA", dataStr, ".//setting.ini");

	uint8_t key_bytes[32] = { 0 };
	uint8_t iv_bytes[16] =  { 0 };
	uint8_t mac[16] = { 0 };
	len = dataStr.GetLength() / 2;
	uint8_t *data = (uint8_t*)malloc(len);
	uint8_t *output = (uint8_t*)malloc(len + 16);
	hexstr2bytes(keyStr, key_bytes);
	hexstr2bytes(ivStr, iv_bytes);
	hexstr2bytes(dataStr, data);

	memset(output, 0, len + 16);
	aes_ctr_encrypt(key_bytes, key_size/8, iv_bytes, data, len, output);
	CString plaintext = "";
	CString strTmp;
	for (int i = 0; i < len; i++)
	{
		strTmp.Format("%02x ", output[i]);
		plaintext = plaintext + strTmp;
	}
	editPlaintext.SetWindowTextA(plaintext);
	//editTagCheckStatus.SetWindowTextA(tagCheck);

	free(data);
	free(output);
}


void CAesTestToolDlg::OnBnClickedButtonDecrypt()
{
	// TODO: 在此添加控件通知处理程序代码
}
