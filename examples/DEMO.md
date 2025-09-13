
# File Opener 데모 시연 가이드

이 문서는 `fileopener://` 커스텀 스킴 데모를 설정하고 실행하는 방법을 안내합니다.

> **Note**
> 기능에 대한 자세한 설계 및 구조는 [FILE_OPENER_DESIGN.md](../FILE_OPENER_DESIGN.md) 문서를 참고하세요.

## 1단계: 의존성 설치

프로젝트의 모든 의존성이 설치되어 있는지 확인하세요.

```bash
npm install
```

## 2단계: 프로토콜 등록

`open-file-demo.js`를 실행하여 `fileopener` 프로토콜을 시스템에 등록합니다.

```bash
node examples/file-opener-demo/open-file-demo.js
```

## 3단계: 프로젝트 별칭 설정

`config-manager.js`를 사용하여 현재 프로젝트를 `protocol-registry`라는 별칭으로 등록합니다.

```bash
node examples/file-opener-demo/config-manager.js add protocol-registry
```

`list` 명령어로 설정이 잘 되었는지 확인할 수 있습니다.

```bash
node examples/file-opener-demo/config-manager.js list
```

## 4단계: 스킴 실행 및 테스트

이제 표준화된 URL을 사용하여 데모 폴더 안의 `open-file-demo.js` 파일을 직접 열어보겠습니다.

```bash
open "fileopener://protocol-registry?path=examples/file-opener-demo/open-file-demo.js"
```

위 명령어를 실행하면, `open-file-demo.js` 파일이 시스템의 기본 편집기에서 열리는 것을 확인할 수 있습니다.


## 5단계: 프로토콜 삭제

데모 사용이 끝나면 아래 명령어를 통해 시스템에 등록된 `fileopener` 프로토콜을 삭제할 수 있습니다.

```bash
node examples/file-opener-demo/deregister-demo.js
```


