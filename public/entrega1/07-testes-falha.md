# Testes de falha

## Caso 1: retorno sem cookie temporário

- **Preparação:** iniciei o login com Google em uma janela comum (`/oauth/login/google`) e parei na página do provedor. Copiei a URL de autorização para uma janela privativa, que não possuía o cookie `__Host-oauth-tx`, e concluí o login nessa segunda janela.
- **Pedido enviado:** retorno do Google para `/oauth/callback/google`, na janela privativa e sem o cookie temporário. Os valores de `code` e `state` não foram registrados aqui porque são transitórios.
- **Resultado esperado:** a rota de retorno deverá recusar a resposta e não criar uma sessão.
- **Resultado observado:** HTTP 400, com a mensagem "Transação ausente". Nenhuma sessão foi criada.

## Caso 2: state alterado

- **Preparação:** iniciei o login em `/oauth/login/google` e, antes de concluir a autenticação, alterei manualmente um único caractere do parâmetro `state` na URL de autorização do Google, prosseguindo o login normalmente em seguida.
- **Pedido enviado:** retorno do Google para `/oauth/callback/google` com o `code` original e o `state` alterado.
- **Resultado esperado:** a rota deveria recusar a resposta antes de trocar o código por token, pois o resumo do `state` alterado não bateria com o valor salvo no D1.
- **Resultado observado:** HTTP 400, confirmando a recusa antes da troca de tokens. Nenhuma sessão foi criada.

## Caso 3: reutilização da transação

- **Preparação:** concluí um login com sucesso. No painel Network, localizei a requisição de retorno (`/oauth/callback/...`) e usei Copy URL.
- **Pedido enviado:** abri novamente no navegador a URL de retorno copiada. A URL não foi registrada aqui porque contém valores transitórios.
- **Resultado esperado:** a transação já terá sido removida e a repetição deverá falhar.
- **Resultado observado:** a repetição falhou: a rota de retorno recusou a requisição e nenhuma nova sessão foi criada.

## Caso 4: sessão expirada

- **Preparação:** com uma sessão de teste criada, abri o console D1 e executei `UPDATE sessions SET expires_at = 0;`.
- **Pedido enviado:** recarreguei a página, que consulta `GET /api/me`.
- **Resultado esperado:** `/api/me` deverá responder 401.
- **Resultado observado:** `/api/me` respondeu 401 e a página passou a mostrar que não há sessão neste navegador.

## Caso 5: origem inválida na saída

- **Preparação:** com uma sessão válida aberta em URL_BASE, abri outra origem (`https://example.com`) em uma segunda aba.
- **Pedido enviado:** no console do navegador, executei `fetch("URL_BASE/oauth/logout", { method: "POST", credentials: "include" })`, com `Origin: https://example.com`.
- **Resultado esperado:** a rota deverá recusar a operação, e a sessão original deverá permanecer válida ao voltar à aba de URL_BASE.
- **Resultado observado:** a rota respondeu 403 (o Firefox exibiu o aviso de CORS, esperado). Ao voltar à aba de URL_BASE, `/api/me` respondeu 200 e a sessão continuou válida.

## Caso 6: reutilização do cookie revogado

- **Preparação:** em uma sessão exclusiva do laboratório, copiei temporariamente o valor do cookie `__Host-session` pelas ferramentas de desenvolvimento e executei o logout.
- **Pedido enviado:** restaurei o mesmo valor do cookie pelo Console e consultei `GET /api/me`. Confirmei no Network que o cookie foi enviado na requisição.
- **Resultado esperado:** como a linha correspondente foi removida do D1, a resposta deverá ser 401.
- **Resultado observado:** `/api/me` respondeu 401 com o cookie revogado sendo enviado. A cópia do valor foi apagada em seguida.
