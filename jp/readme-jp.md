# ADFS 診断トレース

### 重要なお知らせ
---
スクリプト（ADFS-tracing.ps1）は、Active Directory Federation Services または Web Application Proxy Server に関する問題を Microsoft カスタマーサポートサービス（CSS）がトラブルシューティングする際に役立つ情報を収集するために設計されています。  
収集されたデータには、IP アドレス、コンピューター名、ユーザー名など、個人を特定できる情報（PII）や機密データが含まれる場合があります。

スクリプトによって生成されたすべてのデータは、初期化時にユーザーが指定したフォルダーに保存されます。  
トレースが完了すると、スクリプトはサーバー名、日付、時刻を含むアーカイブファイル（zip ファイル）を自動的に生成します。アーカイブ処理が失敗した場合、すべてのデータは指定されたフォルダー内のサブフォルダー（/temporary）に保存されます。

> このスクリプトはインターネット接続を必要とせず、Microsoft に自動的にデータを送信することはありません。  
> このスクリプトで収集されたデータは、**アクティブなサポート契約の一環としてのみ** Microsoft に送信してください。  
> Microsoft に送信するデータは、**必ず**セキュアなファイル転送を通じて送信してください。  
>  
> そのような転送ツールへのアクセスは、サポートインシデントに割り当てられた Microsoft サポート担当者から提供されます。  
> サポート担当者とこの件について、また懸念事項について話し合ってください。  
>  
> https://privacy.microsoft.com/en-us/privacy

---

### スクリプトの使用方法
---
##### 必要条件:
- スクリプトは以下の OS 上の ADFS をサポートします:  
  Windows Server 2012R2 / 2016 / 2019 / 2022 / 2025
- スクリプトを実行するにはローカル管理者権限が必要です。
- 可能であれば、アカウントはドメインユーザーであることが望ましい。
- 長時間トレースを実行する場合、ターゲットフォルダーのあるボリュームに最低 5GB の空きディスク容量が必要です。
- Windows Server 2012R2 では、Windows Management Framework 5.1（WMF）別名 PowerShell 5.0 のインストールが推奨されます（必須ではありません）。  
  WMF は以下から入手できます:  
  https://www.microsoft.com/en-us/download/details.aspx?id=54616

Zip ファイルを緑色の「code」ボタンからダウンロードし、トレース対象のサーバー上の任意の場所に解凍してください。  
スクリプトファイルと「helpermodules」フォルダーがターゲット場所にあることを確認してください。

スクリプトは PowerShell コンソールから実行することを推奨します。

---

##### トレーススクリプトを対話モードで実行する場合:
パラメーターなしでスクリプトを実行すると、フォーム UI が表示され、以下のオプションが提供されます:

| オプション | 説明 |
| :--------: | :--------- |
| Configuration Only | このモードでは静的データのみがエクスポートされます。デフォルトのシナリオです。|
| Runtime Tracing | このモードでは Configuration Only のデータに加え、http.sys、schannel、kerberos/ntlm、ADFS、DRS のデバッグトレースを有効化します。|
| include Network Traces | ランタイムトレース時のみ選択可能で、ネットワークトレースを収集します。|
| include Performance Counters | ランタイムトレース時のみ選択可能で、ADFS のパフォーマンスカウンターを収集します。|
| LDAP Traces | LDAP のデバッグログを有効化します。ADFS セットアップや LDAP 関連の問題のデバッグに使用します。<br>Web Application Proxy サーバーでは利用不可<br><code style="color : Orange">警告: このオプションを開始するとサービスが再起動する場合があります</code>|
| WAP Traces | Web Application Proxy Server Core の高度なデバッグログを有効化します。Exchange OWA、SharePoint On-premise などの WAP 公開アプリケーションの問題をトラブルシュートします。<br>Web Application Proxy サーバーでのみ利用可能|
| Textbox/Browse | データ保存先フォルダーのパスを指定するか、ファイルブラウザーで選択します。|

---

##### コンソールからスクリプトを実行する場合:
スクリプトは UI と同様の 4 つのパラメーターを受け付けます:

| オプション | 説明 |
| :-------- | :--------- |
| -Path | ファイルを保存するフォルダーの絶対パスを指定します。<br>このパラメーターが省略された場合、スクリプトは対話モードで実行され、他のスイッチは無視されます。|
| -Tracing | 省略された場合、スクリプトは構成のみのモードで実行され、オプションのトレーススイッチは無視されます。|
| -NetworkTracing | ネットワークトレースを有効化します。-Tracing が指定されている場合のみ動作します。|
| -PerfTracing | パフォーマンスカウンター収集を有効化します。-Tracing が指定されている場合のみ動作します。|
| -LDAPTracing | LDAP デバッグトレースを有効化します。-Tracing が指定され、ADFS サーバーで実行される場合のみ動作します。|
| -WAPTracing | WAP デバッグトレースを有効化します。-Tracing が指定され、WAP サーバーで実行される場合のみ動作します。|

---

実行中、特にトレースシナリオでは、スクリプトは初期の静的データ収集を開始します。  
複数のマシンでトレースが必要な場合、他のサーバーを設定する時間を与えるために一時停止します。

すべてのサーバーが準備できたら、画面の指示に従って CTRL+Y を押すか、PowerShell ISE では OK をクリックしてトレースを再開します。

その後、データ収集/トレースが実行中であることを示すメッセージが表示されます。  
この時点で、キャプチャしたい問題を再現してください。  
> データサイズを最小限にするため、できるだけ早く問題を再現してください。

問題を再現したら、CTRL+Y（コンソール）または OK（ISE）で収集を停止します。

残りのデータ収集とデバッグトレースのコンパイルには時間がかかります。  
**中断せず、しばらくお待ちください。**

スクリプトが終了したら、圧縮ファイルをサポートエンジニアが提供するワークスペースにアップロードしてください。

---

##### 出力ファイルの参照:

| ファイル名 | 説明 |
| ----------- | ----------- |
| AD FS Tracing-Debug.evtx | ADFS 詳細診断/デバッグイベント |
| AD FS-Admin.evtx | ADFS 管理ログ（高レベルのエラーと情報イベント） |
| Application.evtx | Windows OS アプリケーションイベントログ |
| DRS-Admin.evtx | デバイス登録サービスのイベントログ |
| Device Registration Service Tracing-Debug.evtx | デバイス登録サービスの診断イベント |
| Microsoft-Windows-CAPI2-Operational.evtx | 証明書検証問題を分析するための Crypto API イベント |
| Security.evtx | OS のセキュリティイベントログ（最大 1 時間またはトレース期間） |
| Microsoft-Windows-WebApplicationProxy-Session.evtx | WAP デバッグイベントログ |
| Microsoft-Windows-WebApplicationProxy-Admin.evtx | WAP 管理イベントログ |
| System.evtx | システムイベントログ |
| Hostname-<ADFSBackEnd/ADFSProxy>-perf_<datetime>.blg | トレース期間中のパフォーマンスカウンター情報 |
| Hostname-ADFS-fileversions.txt | 現在インストールされている ADFS バイナリファイルのバージョン |
| Hostname-Certificates-CA.txt | コンピューターの中間認証局証明書ストアの一覧 |
| Hostname-Certificates-My.txt | コンピューターの個人証明書ストアの一覧 |
| Hostname-Certificates-Root.txt | コンピューターのルート CA 証明書ストアの一覧 |
| Hostname-Certificates-NTAuth.txt | コンピューターの NTAuth ストアの一覧 |
| Hostname-Certificates-ADFSTrustedDevices.txt | トレース後に収集された ADFSTrustedDevices ストアの一覧 |
| Hostname-Certificates-CliAuthIssuer.txt | クライアント認証発行者ストアの一覧（ADFS HTTP バインディングで CTL ストアが構成されている場合） |
| Hostname-environment-variables.txt | 登録されているシステム環境変数 |
| Hostname-GPReport.html | スクリプト実行ユーザーとコンピューターに適用されたグループポリシー |
| Hostname-hosts.txt | ホストファイルエントリの一覧 |
| Hostname-ipconfig-all.txt | ネットワークアダプターの TCP/IP 構成 |
| Hostname-Microsoft.IdentityServer.ServiceHost.Exe.Config | ADFS サービス構成ファイル |
| Hostname-sysinfo.txt | システムに関する基本情報 |
| Hostname-netsh-dnsclient-show-state.txt | DNSSEC および DirectAccess 構成情報 |
| Hostname-DNSClient-Cache.txt | DNS クライアントキャッシュエントリ |
| Hostname-netsh-http-show-cacheparam.txt | HTTP キャッシュ構成 |
| Hostname-netsh-http-show-cachestate.txt | HTTP キャッシュ状態 |
| Hostname-netsh-http-show-iplisten.txt | HTTP IP リスナー構成 |
| Hostname-netsh-http-show-servicestate.txt | 登録されている Web アプリケーションエンドポイント一覧 |
| Hostname-netsh-http-show-sslcert.txt | HTTP バインディング構成 |
| Hostname-netsh-http-show-timeout.txt | HTTP ドライバのタイムアウト設定 |
| Hostname-netsh-http-show-urlacl.txt | HTTP の URL 予約 |
| Hostname-netsh-int-advf-show-global.txt | グローバルファイアウォール設定 |
| Hostname-netsh-int-ipv4-show-dynamicport-tcp.txt | IPv4 TCP ポート範囲定義 |
| Hostname-netsh-int-ipv4-show-dynamicport-udp.txt | IPv4 UDP ポート範囲定義 |
| Hostname-netsh-int-ipv6-show-dynamicport-tcp.txt | IPv6 TCP ポート範囲定義 |
| Hostname-netsh-int-ipv6-show-dynamicport-udp.txt | IPv6 UDP ポート範囲定義 |
| Hostname-netsh-winhttp-proxy.txt | システムプロキシ構成の出力 |
| Hostname-NetTCPConnection.txt | 現在確立されているネットワーク接続の一覧 |
| Hostname-network.etl | トレースセッション中に収集されたネットワークトレース |
| Hostname-nltest-trusted_domains.txt | ADFS ドメインが信頼するドメインの一覧 |
| Hostname-reg-ciphers_policy_registry.txt | GPO によって展開された TLS 暗号設定 |
| Hostname-reg-Cryptography_registry.txt | TLS/SSL 暗号化構成のレジストリ出力 |
| Hostname-reg-NETLOGON-port-and-other-params.txt | Netlogon サービスのレジストリ設定 |
| Hostname-reg-NTDS-port-and-other-params.txt | NTDS 設定プロパティのレジストリ出力 |
| Hostname-reg-schannel.txt | SCHannel 構成パラメータ（TLS/SSL 関連） |
| Hostname-DotNetFramework.txt | .NetFramework バージョンと TLS プロトコルサポート |
| Hostname-route-print.txt | ローカルマシンの IP ルーティング構成 |
| Hostname-services-running.txt | 現在実行中のサービス一覧 |
| Hostname-tasklist.txt | 実行中のタスク一覧 |
| Hostname-WindowsPatches.htm | インストール済み Windows 更新プログラム情報 |
| dcloc_krb_ntlmauth.etl | Kerberos および NTLM デバッグトレース（バイナリ形式） |
| http_trace.etl | HTTP ドライバトレース（バイナリ形式） |
| schannel.etl | SCHannel（TLS/SSL プロバイダー）デバッグファイル（バイナリ形式） |
| ldap.etl | LDAP デバッグトレースファイル（バイナリ形式） |
| wap_trace.etl | Web アプリケーションコアデバッグトレース（バイナリ形式） |
| Get-AdfsAccessControlPolicy.txt | 現在定義されているすべてのアクセス制御ポリシーの一覧 |
| Get-AdfsAdditionalAuthenticationRule.txt | グローバル MFA クレームルールの詳細（構成されている場合） |
| Get-AdfsApplicationGroup.txt | 構成された OAUTH2/OpenID アプリケーショングループの概要 |
| Get-AdfsApplicationPermission.txt | Oauth2/OpenID クライアントアプリの構成されたアプリケーション権限の一覧 |
| Get-AdfsAttributeStore.txt | 構成された属性ストア（AD/LDAP/SQL またはカスタム属性ストアプロバイダー）の一覧 |
| Get-AdfsAuthenticationProvider.txt | インストールされている認証プロバイダーの一覧 |
| Get-AdfsAuthenticationProviderWebContent.txt | 認証プロバイダーの Web カスタマイズ（構成されている場合） |
| Get-ADFSAzureMfaAdapterconfig.txt | Azure MFA アダプター構成のエクスポート（構成されている場合） |
| Get-AdfsCertificate.txt | トークンサイン/復号化およびサービス通信に使用される証明書の詳細 |
| Get-AdfsCertificateAuthority.txt | WHFB シナリオにおける ADFS 証明書登録機関の構成 |
| Get-AdfsClaimDescription.txt | すべてのクレーム記述の一覧 |
| Get-AdfsClaimsProviderTrust.txt | 構成されたクレームプロバイダーの詳細構成情報 |
| Get-AdfsClaimsProviderTrustsGroup.txt | 構成されている場合、クレームプロバイダー信頼グループの一覧 |
| Get-AdfsClient.txt | 現在登録されている Oauth2 クライアントの一覧 |
| Get-AdfsDeviceRegistration.txt | デバイス登録設定の詳細 |
| Get-AdfsDeviceRegistrationUpnSuffix.txt | 登録されたデバイス登録ドメインサフィックスの一覧（Get-AdfsRegistrationHosts と同様） |
| Get-AdfsDirectoryProperties.txt | 認証を許可された UPN サフィックス/Netbios 名の一覧（2019+） |
| Get-AdfsEndpoint.txt | 有効/無効な ADFS エンドポイントの一覧 |
| Get-AdfsFarmInformation.txt | 2016/2019 ファーム展開におけるすべての ADFS ファームノードの一覧 |
| Get-AdfsGlobalAuthenticationPolicy.txt | ADFS の認証ハンドラー構成 |
| Get-AdfsGlobalWebContent.txt | 共通 ADFS Web カスタマイズ設定に関する情報 |
| Get-AdfsLocalClaimsProviderTrust.txt | ローカルクレームプロバイダー（AD 組み込みおよび LDAP クレームプロバイダー）の一覧 |
| Get-AdfsNativeClientApplication.txt | 構成された OAuth2/OpenID ネイティブクライアントアプリの一覧 |
| Get-AdfsNonClaimsAwareRelyingPartyTrust.txt | WAP に公開される可能性のある非クレームアプリの一覧 |
| Get-AdfsProperties.txt | ADFS サービス構成プロパティの一覧 |
| Get-AdfsRegistrationHosts.txt | 登録されたデバイス登録ドメインサフィックスの一覧 |
| Get-AdfsRelyingPartyTrust.txt | 現在構成されているすべての信頼パーティアプリケーションの出力 |
| Get-AdfsRelyingPartyTrustsGroup.txt | 信頼パーティグループ構成の一覧 |
| Get-AdfsRelyingPartyWebContent.txt | 構成された信頼パーティの Web コンテンツカスタマイズの一覧 |
| Get-AdfsRelyingPartyWebTheme.txt | 信頼パーティに関連付けられた Web テーマの一覧 |
| Get-AdfsScopeDescription.txt | OpenID スコープ定義 |
| Get-AdfsServerApplication.txt | OAUTH2 サーバーアプリケーション構成の詳細 |
| Get-AdfsSslCertificate.txt | HTTP にバインドされている SSL 証明書 |
| Get-AdfsSyncProperties.txt | WID 展開における
| Get-AdfsTrustedFederationPartner.txt | 信頼されたフェデレーションパートナーの一覧 |
| Get-AdfsWebApiApplication.txt | Oauth2/OpenID Web API 構成設定 |
| Get-AdfsWebApplicationProxyRelyingPartyTrust.txt | WAP 事前認証の信頼パーティ構成の出力 |
| Get-AdfsWebConfig.txt | 現在アクティブなデフォルト Web テーマと Cookie 設定（HomeRealmDiscovery 自動化用） |
| Get-AdfsWebTheme.txt | 構成された ADFS Web テーマの一覧 |
| Get-ServiceAccountDetails.txt | AD DS 内の ADFS サービスアカウント構成の詳細と使用される Kerberos 暗号化の予測 |
| netlogon.bak | Netlogon デバッグログのバックアップファイル（ログファイルが長期間のトレースで 100MB を超えた場合に作成） |
| netlogon.log | Netlogon デバッグログ情報 |
| Get-WebApplicationProxyApplication.txt | 公開されたアプリケーションの一覧 |
| Get-WebApplicationProxyAvailableADFSRelyingParty.txt | フェデレーションサーバーで構成された利用可能な信頼パーティの一覧 |
| Get-WebApplicationProxyConfiguration.txt | グローバル Web Application Proxy 設定 |
| Get-WebApplicationProxyHealth.txt | Web Application Proxy サーバーのヘルスステータス |
| Get-WebApplicationProxySslCertificate.txt | フェデレーションサーバープロキシ用 SSL 証明書のバインディング情報 |
| Get-WebApplicationProxyAdfsTimeSkew.txt | バックエンド ADFS への呼び出しによるタイムスキューのテスト |
| HOSTNAME-Microsoft.IdentityServer.ProxyService.exe.config | プロキシサービス構成ファイル |
| transscript_output.txt | スクリプト実行に関する診断/テレメトリ情報 |
| Wid \ error<int>.log | WID エラーログ（WID 展開時のみ収集、ファイルの累積サイズが 10MB 以下の場合） |