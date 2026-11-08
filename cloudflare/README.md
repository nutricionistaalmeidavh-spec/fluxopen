# FluxOpen — hospedagem Cloudflare gratuita

Esta é a implementação alternativa do painel. O backend FastAPI em Docker e a versão self-hosted continuam disponíveis sem alteração.

## Arquitetura
- Cloudflare Workers: interface mobile-first, autenticação privada e API.
- Cloudflare D1: alvos, autorizações, execuções e relatórios.
- GitHub Actions: containers dos 10 scanners de segurança, separados do Worker.
- Retorno dos relatórios do GitHub Actions para o Worker com HMAC.

Nenhum serviço pago é necessário para o núcleo dentro das cotas gratuitas do Cloudflare e GitHub Actions.

## Recursos criados
- Worker: fluxopen-security
- URL: https://fluxopen-security.nutricionistaalmeidavh.workers.dev
- Banco D1: fluxopen-security
- Workflow: .github/workflows/scan.yml

## Secrets de configuração
No Cloudflare Worker, configure como secret:
- ADMIN_PASSWORD: senha forte e exclusiva com pelo menos 12 caracteres.
- SCAN_SIGNING_SECRET: string aleatória de pelo menos 32 caracteres. Use o MESMO valor no secret GitHub Actions SCAN_SIGNING_SECRET.
- GH_TOKEN: token fine-grained GitHub restrito ao repositório nutricionistaalmeidavh-spec/fluxopen, com Actions Read and Write.

Sem GH_TOKEN, é possível cadastrar alvos e consultar o painel, mas o disparo remoto retorna erro 503 de forma intencional. Nunca salve tokens no código Git ou na interface pública.

Antes de auditar clientes, mude a visibilidade do repositório para privado. Verifique limites de Actions para repositórios privados.

## Passos
1. Entre no endereço workers.dev pelo celular e faça login.
2. Cadastre o domínio com a referência e a validade da autorização.
3. Selecione o alvo e os 10 módulos ou apenas o conjunto necessário.
4. Dispare a auditoria. O workflow retorna relatório assinado e artefatos; exporte JSON ou HTML.

## Migração e reprodução
O código está em cloudflare/worker.mjs e cloudflare/panel.mjs. O Worker recebe o binding D1 chamado DB. O schema está em cloudflare/schema.sql. Para versões futuras, preserve os secrets e o binding na atualização.

## Garantias e limites
- URLs apenas HTTP(S) com domínios públicos, sem IPs privados e portas arbitrárias.
- HMAC assina cada execução e os resultados recebidos.
- Runner revalida DNS para rejeitar endereços internos antes de executar.
- Subfinder não adiciona subdomínios ao escopo.
- SQLmap só faz testes se houver parâmetros explícitos na URL.
- Ferramentas ativas exigem confirmação específica.
- O painel depende das franquias gratuitas do Cloudflare e GitHub Actions, não oferece garantia de custos ilimitados.

Teste sem executar scans: node --test tests/test_worker.mjs

## Verificação sem varreduras
Para testar o transporte Worker → Actions → callback → D1, a API autenticada
`POST /api/scans` aceita `verification_only: true`, além dos campos normais.
O workflow existente valida o manifesto HMAC e os argumentos dos módulos sem
resolver DNS, iniciar containers ou acessar o alvo. O relatório inclui
`verification_only: true`, com todos os módulos marcados como ignorados e uma
explicação explícita de teste. Isso valida a integração, não a detecção dos scanners.
Falhas no callback fazem o workflow falhar, evitando sucesso silencioso sem entrega.

## Login automático com Apple Face ID / chave-senha

O painel Cloudflare tem suporte a **passkeys (WebAuthn ES256)**, sem SaaS ou serviço pago.

Primeiro acesso seguro:
1. Faça uma única entrada com a senha de administrador atual (`ADMIN_PASSWORD` no Cloudflare). Caso não a conheça, substitua o secret `ADMIN_PASSWORD` nas configurações do Worker por uma nova senha de **no mínimo 12 caracteres**.
2. Abra **Segurança / Face ID** e toque em **Criar chave-senha no iPhone (Face ID)**.
3. Confirme o Face ID na tela do iOS. Na próxima visita, use **Entrar com Face ID** ou a sugestão automática de chave-senha do Safari.
4. Opcional: na mesma tela, cadastre um **e-mail e senha próprios** (mínimo 12 caracteres) para login alternativo.

A criação de passkeys exige uma sessão administrativa válida e proteção CSRF. Verificações server-side: challenge único e expirável, origem HTTPS exata, RP ID, presença e verificação do usuário (Face ID/PIN), algoritmo ES256, assinatura e contador do autenticador. Dados públicos ficam no D1; **nenhum dado biométrico ou chave privada chega ao servidor**.

**Limitação importante:** o e-mail cadastrado serve como identificador do login com senha, mas **não envia links de recuperação nem verifica posse da caixa postal**; recuperar acesso depende do secret administrativo no Cloudflare ou de uma passkey já cadastrada. A chave-senha é associada ao hostname `fluxopen-security.nutricionistaalmeidavh.workers.dev`. Se mudar para um domínio próprio, registre outra chave-senha. O Face ID depende do suporte do Safari/iOS e da configuração de chaves-senha do aparelho.
