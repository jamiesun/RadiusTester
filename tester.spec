# -*- mode: python -*-
a = Analysis(['tester.py'],
             pathex=['e:\\github\\RadiusTester'],
             hiddenimports = ['gevent'],
             hookspath="")
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          name=os.path.join('dist', 'tester.exe'),
          debug=False,
          strip=None,
          upx=True,
          console=True , icon='tester.ico')
