
// AesTestToolDlg.h: 头文件
//

#pragma once


// CAesTestToolDlg 对话框
class CAesTestToolDlg : public CDialogEx
{
// 构造
public:
	CAesTestToolDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_AESTESTTOOL_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	int hexstr2bytes(CString str, uint8_t* ouput);
	void LoadInputData();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButtonEncrypt();
	CEdit editPlaintext;
	CComboBox mCboxAes;
	CComboBox mCboxKey;
	CComboBox mCboxPadd;
	CEdit mEditKey;
	CEdit mEditIv;
	CEdit mEditInputData;
	CEdit mEditMac;
	CButton mCheckMac;
	CEdit mMacStatus;
};
