# ADFS 診断トレース

### 重要事項

---

本スクリプト (ADFS-tracing.ps1) は、Active Directory Federation Services または Web Application Proxy サーバーに関して問題が生じた際に、Microsoft カスタマー サービス & サポート (CSS) がトラブルシューティングを目的として有効となる情報を収集するためのものです。収集されたデータには、IP アドレス、コンピューター名、ユーザー名など、個人を特定できる情報 (PII) や機密データが含まれる場合があります。

スクリプトによって生成されたすべてのデータは、最初の実行時にユーザーにより指定されたフォルダーに保存されます。トレースが完了すると、スクリプトはサーバー名、日付、時刻を含むアーカイブ ファイル (zip ファイル) を自動的に生成します。アーカイブ処理が失敗した場合、すべてのデータは指定されたフォルダー内のサブフォルダー (/temporary) に保存されます。

> このスクリプトはインターネット接続を必要とせず、また Microsoft に自動的にデータを送信することはありません。このスクリプトで収集されたデータは、**アクティブなサポート契約の一環としてのみ** Microsoft に送信ください。Microsoft にデータを送信する際は、**必ず** セキュアなファイル転送を通じて実施ください。  
> 
> 転送ツールへのアクセスは、サポート インシデントに割り当てられた Microsoft サポート担当者から提供されます。ツールをご利用の際に懸念事項がある場合は、サポート エンジニアにご相談ください。
>  
> https://privacy.microsoft.com/en-us/privacy

---

### スクリプトの使用方法

---

##### 必要条件:

- スクリプトは Windows Server 2012R2 / Windows Server 2016 / Windows Server 2019 / Windows Server 2022 and Windows Server 2025 OS 上の ADFS をサポートします。
- スクリプトを実行するにはローカル管理者権限が必要です。
- 可能であれば、アカウントはドメイン ユーザーを利用ください。
- 長時間トレースを実行する場合は、対象フォルダーのあるディスクに最低 5GB の空きディスク容量が必要です。
- Windows Server 2012 R2 では、Windows Management Framework (WMF) 5.1 (PowerShell 5.0) のインストールが推奨されます (必須ではない) 。WMF はこちらから入手可能です: https://www.microsoft.com/en-us/download/details.aspx?id=54616

Zip ファイルダウンロードするには、緑色の「code」ボタンを押下し、トレース対象のサーバー上の任意の場所に解凍ください。スクリプト ファイルと「helpermodules」フォルダーが指定した場所にあることを確認ください。

スクリプトは PowerShell コンソールから実行することを推奨します。

---

##### トレーススクリプトを対話モードで実行する場合:

パラメーターなしでスクリプトを実行すると、フォーム画面が表示され、以下のオプションが提供されます:

| オプション | 説明 |
| :--------: | :--------- |
| Configuration Only | このモードでは静的なデータのみがエクスポートされます。もっとも一般的なシナリオです。|
| Runtime Tracing | このモードでは Configuration Only のデータに加え、http.sys、schannel、kerberos/ntlm、ADFS、DRS のデバッグ トレースを有効化して取得します。|
| Include Network Traces | 事象の再現中にトレースを取得する場合にのみ選択可能で、ネットワーク トレースを収集します。|
| Include Performance Counters | 事象の再現中にトレースを取得する場合にのみ選択可能で、ADFS のパフォーマンス カウンターを収集します。|
| LDAP Traces | LDAP のデバッグ ログを有効化します。ADFS のセットアップや LDAP 関連の問題のデバッグに使用します。<br>本オプションは Web Application Proxy サーバーでは利用不可です。<br><code style="color : Orange">警告: このオプションを開始するとサービスが再起動する場合があります</code>|
| WAP Traces | Web Application Proxy サーバー コアの高度なデバッグ ログを有効化します。Exchange OWA、SharePoint オンプレミスなどの WAP 公開アプリケーションの問題をトラブルシュートするのに利用します。<br>Web Application Proxy サーバーでのみ利用可能なオプションです。 |
| Textbox/Browse | データ保存先のフォルダーのパスを指定するのに使用します。ファイルの保存先は、ファイル エクスプローラーをご利用いただいても結構です。 |

---

##### コンソールからスクリプトを実行する場合:

スクリプトは画面から実行した場合と同様に 4 つのパラメーターを受け付けます:

| オプション | 説明 |
| :-------- | :--------- |
| -Path | ファイルを保存するフォルダーの絶対パスを指定します。<br>このパラメーターが省略された場合、スクリプトは対話モードで実行され、他のオプションは無視されます。 |
| -Tracing | 省略された場合、スクリプトは Configuration Only のモードで実行され、オプションで指定されたトレースは無視されます。 |
| -NetworkTracing | ネットワーク トレースを有効化します。-Tracing が指定されている場合のみ動作します。 |
| -PerfTracing | パフォーマンス カウンターの収集を有効化します。-Tracing が指定されている場合のみ動作します。 |
| -LDAPTracing | LDAP デバッグ トレースを有効化します。-Tracing が指定され、ADFS サーバー上で実行される場合のみ動作します。 |
| -WAPTracing | WAP デバッグ トレースを有効化します。-Tracing が指定され、WAP サーバー上で実行される場合のみ動作します。 |

---

事象の再現中に実行する場合、特にトレースを取得するシナリオの場合は、スクリプトは最初に静的データ収集を開始します。複数のマシンでトレースが必要な場合、他のサーバーでも設定に時間をかけられるようスクリプトは一旦動作を停止します。

すべてのサーバーが準備できたら、画面の指示に従って CTRL+Y を押すか、PowerShell ISE では OK をクリックしてトレースを再開します。

その後、データ収集/トレースが実行中であることを示すメッセージが表示されます。  
この時点で、キャプチャしたい問題を再現ください。  

> データのサイズを最小限にするため、できるだけ素早く問題を再現ください。

問題を再現したら、CTRL+Y (コンソールの場合) または OK (ISE の場合) で収集を停止します。

残りのデータ収集とデバッグ トレースのコンパイルには時間がかかる場合があります。**時間がかかっていても中断せず、しばらくお待ちください。**

スクリプトが終了したら、サポート エンジニアにより提供されたワークスペースに圧縮したファイルをアップロードください。

---

##### 出力ファイルの参照:

| ファイル名 | 説明 |
| ----------- | ----------- |
| AD FS Tracing-Debug.evtx | ADFS の詳細診断/デバッグ イベント ログ |
| AD FS-Admin.evtx | ADFS の管理ログ (エラーや情報などのイベント ログ) |
| Application.evtx | Windows OS のアプリケーション イベント ログ |
| DRS-Admin.evtx | デバイス登録サービスのイベント ログ |
| Device Registration Service Tracing-Debug.evtx | デバイス登録サービスの診断イベント ログ |
| Microsoft-Windows-CAPI2-Operational.evtx | 証明書の検証に関する問題を分析するための Crypto API イベント ログ |
| Security.evtx | OS のセキュリティ イベント ログ (サイズは最大で 1 時間またはトレースを取得した期間のになります)  |
| Microsoft-Windows-WebApplicationProxy-Session.evtx | WAP デバッグ イベント ログ |
| Microsoft-Windows-WebApplicationProxy-Admin.evtx | WAP の管理イベント ログ |
| System.evtx | システム イベント ログ |
| Hostname-<ADFSBackEnd/ADFSProxy>-perf_<datetime>.blg | トレース期間中のパフォーマンス カウンター情報 |
| Hostname-ADFS-fileversions.txt | 現在インストールされている ADFS バイナリ ファイルのバージョン |
| Hostname-Certificates-CA.txt | コンピューターの中間認証局証明書ストアの一覧 |
| Hostname-Certificates-My.txt | コンピューターの個人証明書ストアの一覧 |
| Hostname-Certificates-Root.txt | コンピューターのルート CA 証明書ストアの一覧 |
| Hostname-Certificates-NTAuth.txt | コンピューターの NTAuth ストアの一覧 |
| Hostname-Certificates-ADFSTrustedDevices.txt | トレース後に収集された ADFSTrustedDevices ストアの一覧 |
| Hostname-Certificates-CliAuthIssuer.txt | ClientAuthIssuers ストアの一覧 (ADFS HTTP バインディングで CTL ストアが構成されている場合)  |
| Hostname-environment-variables.txt | 登録されているシステム環境変数 |
| Hostname-GPReport.html | スクリプト実行ユーザーとコンピューターに適用されたグループ ポリシー |
| Hostname-hosts.txt | ホスト ファイルのエントリの一覧 |
| Hostname-ipconfig-all.txt | ネットワーク アダプターの TCP/IP の構成 |
| Hostname-Microsoft.IdentityServer.ServiceHost.Exe.Config | ADFS サービスの構成ファイル |
| Hostname-sysinfo.txt | システムに関する基本情報 |
| Hostname-netsh-dnsclient-show-state.txt | DNSSEC および DirectAccess の構成情報 |
| Hostname-DNSClient-Cache.txt | DNS クライアントのキャッシュ エントリ |
| Hostname-netsh-http-show-cacheparam.txt | HTTP のキャッシュ構成 |
| Hostname-netsh-http-show-cachestate.txt | HTTP のキャッシュ状態 |
| Hostname-netsh-http-show-iplisten.txt | HTTP IP のリスナー構成 |
| Hostname-netsh-http-show-servicestate.txt | 登録されている Web アプリケーション エンドポイントの一覧 |
| Hostname-netsh-http-show-sslcert.txt | HTTP バインディングの構成 |
| Hostname-netsh-http-show-timeout.txt | HTTP ドライバのタイムアウト設定 |
| Hostname-netsh-http-show-urlacl.txt | HTTP における URL 予約 |
| Hostname-netsh-int-advf-show-global.txt | グローバル ファイアウォールの設定 |
| Hostname-netsh-int-ipv4-show-dynamicport-tcp.txt | IPv4 TCP ポート範囲の定義 |
| Hostname-netsh-int-ipv4-show-dynamicport-udp.txt | IPv4 UDP ポート範囲の定義 |
| Hostname-netsh-int-ipv6-show-dynamicport-tcp.txt | IPv6 TCP ポート範囲の定義 |
| Hostname-netsh-int-ipv6-show-dynamicport-udp.txt | IPv6 UDP ポート範囲の定義 |
| Hostname-netsh-winhttp-proxy.txt | システム プロキシ構成の出力 |
| Hostname-NetTCPConnection.txt | 現在確立されているネットワーク接続の一覧 |
| Hostname-network.etl | トレース セッション中に収集されたネットワーク トレース |
| Hostname-nltest-trusted_domains.txt | ADFS ドメインが信頼するドメインの一覧 |
| Hostname-reg-ciphers_policy_registry.txt | GPO によって展開された TLS 暗号設定 |
| Hostname-reg-Cryptography_registry.txt | TLS/SSL 暗号化構成のレジストリ出力 |
| Hostname-reg-NETLOGON-port-and-other-params.txt | Netlogon サービスのレジストリ設定 |
| Hostname-reg-NTDS-port-and-other-params.txt | NTDS 設定プロパティのレジストリ出力 |
| Hostname-reg-schannel.txt | SCHannel 構成パラメータ (TLS/SSL 関連) |
| Hostname-DotNetFramework.txt | .NetFramework バージョンと TLS プロトコルサポート |
| Hostname-route-print.txt | ローカル マシンの IP ルーティング構成 |
| Hostname-services-running.txt | 現在実行中のサービス一覧 |
| Hostname-tasklist.txt | 実行中のタスク一覧 |
| Hostname-WindowsPatches.htm | インストール済み Windows 更新プログラム情報 |
| dcloc_krb_ntlmauth.etl | Kerberos および NTLM デバッグトレース (バイナリ形式) |
| http_trace.etl | HTTP ドライバトレース (バイナリ形式) |
| schannel.etl | SCHannel (TLS/SSL プロバイダー) デバッグファイル (バイナリ形式) |
| ldap.etl | LDAP デバッグトレースファイル (バイナリ形式) |
| wap_trace.etl | Web アプリケーションコアデバッグトレース (バイナリ形式) |
| Get-AdfsAccessControlPolicy.txt | 現在定義されているすべてのアクセス制御ポリシーの一覧 |
| Get-AdfsAdditionalAuthenticationRule.txt | グローバル MFA クレームルールの詳細 (構成されている場合) |
| Get-AdfsApplicationGroup.txt | 構成済み OAuth2/OpenID アプリケーション グループの概要 |
| Get-AdfsApplicationPermission.txt | OAuth2/OpenID クライアント アプリの構成済みアプリケーション権限の一覧 |
| Get-AdfsAttributeStore.txt | 構成済み属性ストア (AD/LDAP/SQL またはカスタム属性ストアプロバイダー) の一覧 |
| Get-AdfsAuthenticationProvider.txt | インストールされている認証プロバイダーの一覧 |
| Get-AdfsAuthenticationProviderWebContent.txt | 認証プロバイダーの Web カスタマイズ (構成されている場合) |
| Get-ADFSAzureMfaAdapterconfig.txt | Azure MFA アダプター構成のエクスポート (構成されている場合) |
| Get-AdfsCertificate.txt | トークンの署名/復号およびサービス通信に使用される証明書の詳細 |
| Get-AdfsCertificateAuthority.txt | WHFB シナリオにおける ADFS 証明書登録機関の構成 |
| Get-AdfsClaimDescription.txt | すべてのクレーム記述の一覧 |
| Get-AdfsClaimsProviderTrust.txt | 構成されたクレーム プロバイダーの詳細構成情報 |
| Get-AdfsClaimsProviderTrustsGroup.txt | (構成されている場合) クレーム プロバイダー信頼グループの一覧 |
| Get-AdfsClient.txt | 現在登録されている OAuth2 クライアントの一覧 |
| Get-AdfsDeviceRegistration.txt | デバイス登録設定の詳細 |
| Get-AdfsDeviceRegistrationUpnSuffix.txt | 登録されたデバイス登録ドメイン サフィックスの一覧 (Get-AdfsRegistrationHosts と同様)  |
| Get-AdfsDirectoryProperties.txt | 認証を許可された UPN サフィックス/Netbios 名の一覧 (2019+)  |
| Get-AdfsEndpoint.txt | 有効/無効な ADFS エンドポイントの一覧 |
| Get-AdfsFarmInformation.txt | 2016/2019 ファーム展開におけるすべての ADFS ファーム ノードの一覧 |
| Get-AdfsGlobalAuthenticationPolicy.txt | ADFS の認証ハンドラーの構成 |
| Get-AdfsGlobalWebContent.txt | 共通した ADFS の Web カスタマイズ設定に関する情報 |
| Get-AdfsLocalClaimsProviderTrust.txt | ローカル クレーム プロバイダー (AD 組み込みおよび LDAP クレームプロバイダー) の一覧 |
| Get-AdfsNativeClientApplication.txt | 構成された OAuth2/OpenID ネイティブクライアントアプリの一覧 |
| Get-AdfsNonClaimsAwareRelyingPartyTrust.txt | WAP に公開される可能性のある非クレーム アプリの一覧 |
| Get-AdfsProperties.txt | ADFS サービス構成プロパティの一覧 |
| Get-AdfsRegistrationHosts.txt | 登録されたデバイス登録ドメイン サフィックスの一覧 |
| Get-AdfsRelyingPartyTrust.txt | 現在構成されているすべての証明書利用者信頼の出力 |
| Get-AdfsRelyingPartyTrustsGroup.txt | 証明書利用者信頼のグループ構成の一覧 |
| Get-AdfsRelyingPartyWebContent.txt | 構成された証明書利用者信頼の Web コンテンツカスタマイズの一覧 |
| Get-AdfsRelyingPartyWebTheme.txt | 証明書利用者信頼に関連付けられた Web テーマの一覧 |
| Get-AdfsScopeDescription.txt | OpenID スコープ定義 |
| Get-AdfsServerApplication.txt | OAuth2 サーバー アプリケーション構成の詳細 |
| Get-AdfsSslCertificate.txt | HTTP にバインドされている SSL 証明書 |
| Get-AdfsSyncProperties.txt | WID 展開における AD FS のデータベースの同期状態 |
| Get-AdfsTrustedFederationPartner.txt | * |
| Get-AdfsWebApiApplication.txt | OAuth2/OpenID の Web API 構成設定 |
| Get-AdfsWebApplicationProxyRelyingPartyTrust.txt | WAP 事前認証の証明書利用者信頼の構成の出力 |
| Get-AdfsWebConfig.txt | 現在アクティブなデフォルト Web テーマと Cookie 設定 (HomeRealmDiscovery の自動化用)  |
| Get-AdfsWebTheme.txt | 構成された ADFS Web テーマの一覧 |
| Get-ServiceAccountDetails.txt | AD DS 内の ADFS サービス アカウント構成の詳細と使用される Kerberos 暗号化の予測 |
| netlogon.bak | Netlogon デバッグログのバックアップ ファイル (ログファイルが長期間のトレースで 100MB を超えた場合に作成)  |
| netlogon.log | Netlogon デバッグログ情報 |
| Get-WebApplicationProxyApplication.txt | 公開されたアプリケーションの一覧 |
| Get-WebApplicationProxyAvailableADFSRelyingParty.txt | フェデレーション サーバーで構成された利用可能な証明書利用者信頼の一覧 |
| Get-WebApplicationProxyConfiguration.txt | Web Application Proxy サーバーの全体の設定 |
| Get-WebApplicationProxyHealth.txt | Web Application Proxy サーバーの健全性状態 |
| Get-WebApplicationProxySslCertificate.txt | フェデレーション サーバープロキシ用の SSL 証明書のバインディング情報 |
| Get-WebApplicationProxyAdfsTimeSkew.txt | バックエンドの ADFS への呼び出しを行った際に生じた時間差の確認結果 |
| HOSTNAME-Microsoft.IdentityServer.ProxyService.exe.config | プロキシ サービスの構成ファイル |
| transscript_output.txt | スクリプト実行に関する診断/テレメトリ情報 |
| Wid \ error<int>.log | WID エラーログ (WID 展開時のみ収集、ファイルの累積サイズが 10MB 以下の場合) |
