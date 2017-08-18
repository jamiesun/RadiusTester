# -*- mode: python -*-
a = Analysis(['qtester.py'],
             pathex=['z:\\github\\RadiusTester'],
             hiddenimports = ['gevent'],
             hookspath="")
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name=os.path.join('dist', 'qtester.exe'),
          debug=False,
          strip=None,
          upx=False,
          console=False , icon='tester.ico')
