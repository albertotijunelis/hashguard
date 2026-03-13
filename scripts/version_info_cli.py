# UTF-8
#
# For more details about fixed file info 'ffi' see:
# http://msdn.microsoft.com/en-us/library/ms646997.aspx
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 4, 0),
    prodvers=(1, 0, 4, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          u'040904B0',
          [
            StringStruct(u'CompanyName', u'HashGuard'),
            StringStruct(u'FileDescription', u'HashGuard CLI - File Verification & Threat Intelligence'),
            StringStruct(u'FileVersion', u'1.1.3.0'),
            StringStruct(u'InternalName', u'hashguard'),
            StringStruct(u'LegalCopyright', u'Copyright (c) 2026 Alberto Tijunelis Neto. Elastic License 2.0.'),
            StringStruct(u'OriginalFilename', u'hashguard.exe'),
            StringStruct(u'ProductName', u'HashGuard'),
            StringStruct(u'ProductVersion', u'1.1.3.0'),
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
