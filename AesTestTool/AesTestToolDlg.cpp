
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



void CAesTestToolDlg::OnBnClickedButtonEncrypt()
{
	uint8_t msg[16] = { 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15 };
	uint8_t mac[16] = { 0 };
	uint8_t key[32];
	uint8_t output[32];
	uint32_t len = sizeof(msg);
	uint8_t iv[16] = { 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	for (int i = 0; i < 32; i++)
	{
		key[i] = i;
	}
	memset(output, 0, sizeof(output));
	aes_ctr_encrypt(key, 16, iv, msg, sizeof(msg), output);
	CString plaintext = "";
	CString strTmp;
	for (int i = 0; i < len; i++)
	{
		strTmp.Format("%02x ", output[i]);
		plaintext = plaintext + strTmp;
	}
	editPlaintext.SetWindowTextA(plaintext);
	//editTagCheckStatus.SetWindowTextA(tagCheck);
}
