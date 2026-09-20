# Kaneki Store — login por Gmail

Fluxo de acesso:
1. A pessoa abre o site e vê apenas a tela para informar o Gmail.
2. Ao continuar, o site abre o Google OAuth para confirmar que ela realmente controla aquele Gmail.
3. Se o Gmail for o proprietário (`dina184513@gmail.com`) ou estiver autorizado pelo proprietário, o painel aparece.
4. Se não estiver autorizado, o servidor bloqueia o acesso.

Importante: digitar um Gmail sozinho não comprova propriedade. Por isso a confirmação final é feita pelo Google OAuth.

## Configuração
Copie `.env.example` para `.env` e configure `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GOOGLE_CALLBACK_URL` e `SESSION_SECRET`.

O proprietário inicial é `dina184513@gmail.com`. Ele pode conceder/remover acesso a outros Gmail pelo painel.
