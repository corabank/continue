import { MessageOptions, authentication, AuthenticationProvider, AuthenticationProviderAuthenticationSessionsChangeEvent, AuthenticationSession, Disposable, env, EventEmitter, ExtensionContext, ProgressLocation, Uri, UriHandler, window } from "vscode";
import { v4 as uuid } from 'uuid';
import { ModelAuthenticatorDescription } from 'core';

class UriEventHandler extends EventEmitter<Uri> implements UriHandler {
    public handleUri(uri: Uri) {
        this.fire(uri);
    }
}

export class ModelAuthenticationProvider implements AuthenticationProvider, Disposable {
    private _sessionChangeEmitter = new EventEmitter<AuthenticationProviderAuthenticationSessionsChangeEvent>();
    private _disposable: Disposable;
    private _pendingStates: string[] = [];
    private _uriHandler = new UriEventHandler();
    private _config: ModelAuthenticatorDescription;
    private _sessionsSecretKey: string;

    constructor(private readonly context: ExtensionContext, private readonly config: ModelAuthenticatorDescription) {
        this._config = config;
        this._disposable = Disposable.from(
            authentication.registerAuthenticationProvider(config.id, config.name, this, { supportsMultipleAccounts: false }),
            window.registerUriHandler(this._uriHandler)
        );
        
        this._sessionsSecretKey = `${config.id}.sessions`;
    }

    get onDidChangeSessions() {
        return this._sessionChangeEmitter.event;
    }

    /**
     * Get the existing sessions
     * @param scopes 
     * @returns 
     */
    public async getSessions(scopes?: string[]): Promise<readonly AuthenticationSession[]> {
        const allSessions = await this.context.secrets.get(this._sessionsSecretKey);

        if (allSessions) {
            return JSON.parse(allSessions) as AuthenticationSession[];
        }

        return [];
    }

    /**
     * Create a new auth session
     * @param scopes 
     * @returns 
     */
    public async createSession(scopes: string[]): Promise<AuthenticationSession> {
        // try {
        const accessToken = await this.login(scopes);

        if (!accessToken) {
            throw new Error(`Cora Auth login failure`);
        }

        const userinfo: { name: string, email: string } = await this.getUserInfo(accessToken);

        const session: AuthenticationSession = {
            id: uuid(),
            accessToken: accessToken,
            account: {
                label: userinfo.name,
                id: userinfo.email
            },
            scopes: scopes
        };

        await this.context.secrets.store(this._sessionsSecretKey, JSON.stringify([session]));

        this._sessionChangeEmitter.fire({ added: [session], removed: [], changed: [] });

        return session;
        // } catch (e) {
        //     window.showErrorMessage(`Sign in failed: ${e}`);
        //     throw e;
        // }
    }

    /**
     * Remove an existing session
     * @param sessionId 
     */
    public async removeSession(sessionId: string): Promise<void> {
        const allSessions = await this.context.secrets.get(this._sessionsSecretKey);
        if (allSessions) {
            let sessions = JSON.parse(allSessions) as AuthenticationSession[];
            const sessionIdx = sessions.findIndex(s => s.id === sessionId);
            const session = sessions[sessionIdx];
            sessions.splice(sessionIdx, 1);

            await this.context.secrets.store(this._sessionsSecretKey, JSON.stringify(sessions));

            if (session) {
                this._sessionChangeEmitter.fire({ added: [], removed: [session], changed: [] });
            }
        }
    }

    /**
     * Dispose the registered services
     */
    public async dispose() {
        this._disposable.dispose();
    }

    private async login(scopes: string[] = []) {
        const stateId = uuid();
        this._pendingStates.push(stateId);

        const scopeString = scopes.join(' ');

        if (!scopes.includes('openid')) {
            scopes.push('openid');
        }
        if (!scopes.includes('profile')) {
            scopes.push('profile');
        }
        if (!scopes.includes('email')) {
            scopes.push('email');
        }

        // Get the device code (back channel)
        const deviceCodeResponse = await fetch(`${this.config.baseUrl}${this.config.deviceCodeEndpoint}`, {
            method: 'POST',
            headers: {
                "Content-Type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({
            client_id: this.config.clientId,
            scope: scopeString
            }).toString()
        });
        if (!deviceCodeResponse.ok) {
            throw new Error('Failed to get the device code');
        }
        const deviceCodeData = await deviceCodeResponse.json();

        const userVerifyMessage = `Vamos iniciar o processo de login com sua conta Cora.`;

        const options: MessageOptions = { detail: 'Você será redirecionado para seu navegador.', modal: true };

        const selection = await window.showInformationMessage(userVerifyMessage, options, 'Start');
        if (selection !== 'Start') {
            throw new Error('Operation cancelled.');
        }
        const disp = await env.openExternal(Uri.parse(deviceCodeData.verification_uri_complete));

        // Confirm that the user has finished authenticating before continuing
        const userPrompt = "Selecione 'Continue' após terminar o login no seu navegador.";
        // let userInput = "";
        const userInput = await window.showInformationMessage(userPrompt, options, 'Continue');
        
        if (userInput !== 'Continue') {
            throw new Error('Operation cancelled.');
        }
        
        const tokenResponse = await fetch(`${this.config.baseUrl}${this.config.tokenEndpoint}`, {
        method: 'POST',
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            client_id: this.config.clientId,
            device_code: deviceCodeData.device_code
        }).toString()
        });

        if (!tokenResponse.ok) {
            console.error(tokenResponse.json());
            throw new Error('Failed to get the token');
        }

        const tokenData = await tokenResponse.json();

        // TODO: save refresh token
        return tokenData.access_token;
                
    }

    /**
     * Get the user info from Auth0
     * @param token 
     * @returns 
     */
    private async getUserInfo(token: string) {
        // const fetch = await import('node-fetch');
        const response = await fetch(`${this.config.baseUrl}${this.config.userInfoEndpoint}`, {
            headers: {
                Authorization: `Bearer ${token}`
            }
        });
        return await response.json();
    }
}





