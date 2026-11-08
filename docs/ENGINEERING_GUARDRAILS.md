# FluxOpen — P0–P5: requisitos de release e recuperação

Base de integração: `main` commit `b2481d4a9c0d737edcf6091f86ad30709f295b1f` (2026-11-08).
As verificações são reproduzíveis no GitHub Actions em `.github/workflows/ci.yml`.

## Contratos imutáveis (P0)
- Não modificar ou expor `ADMIN_PASSWORD`, `SCAN_SIGNING_SECRET` e `GH_TOKEN`. Variáveis/bindings existentes continuam em seus locais originais.
- Banco D1 `DB` e tabelas `sessions`, `targets`, `scans`, `admin_identity`, `passkeys`, `webauthn_challenges`, `scan_dispatch` e `login_failures`: sem migrações destrutivas.
- HMAC, manifesto assinado, WebAuthn/passkeys, CSRF, sessão e escopo autorizado preservados.
- Nenhum serviço pago obrigatório; scanners são open source, GitHub Actions + Cloudflare gratuito ou infraestrutura self-hosted existente.
- Não modificar o relatório assinado gravado: interpretação amigável e ocultação de dados apenas na apresentação.

## P1 — callback seguro
- Verificar HMAC antes de carregar ou processar o JSON.
- Validar módulos, ferramentas permitidas, achados e tamanhos.
- Finalizar auditoria somente uma vez, com atualização condicional atômica em D1; repetição/concorrência -> HTTP 409.
- Cobertura: `tests/test_callback_integration.mjs`, `tests/test_worker.mjs`, `tests/test_passkeys.mjs`.

## P2 — confiabilidade dos scanners
- Nuclei: impedir consulta automática de update na inicialização sem ampliar taxa nem escopo; timeout preservado como limite, sem inventar sucesso.
- Nikto: saída de uso/ajuda não significa scanner executado.
- FFUF: autocalibração para reduzir falso positivo SPA; taxa máxima 2 req/s, 1 thread.
- ZAP: falha de geração de relatório estruturado é sinalizada; preservar recuperação dos avisos em stdout.
- Auditoria totalmente ignorada não aparece como concluída sem ressalvas.
- Cobertura: `tests/test_runner_reliability.py`, `tests/test_runner_findings.py`, smoke Docker existente.

## P3 — relatório amigável
- Preservar `cloudflare/report-layout.mjs` como renderizador profissional.
- Métricas não contam `skipped` como executadas, cobertura incompleta é destacada.
- Exportações HTML/JSON usam nomes amigáveis existentes; JSON técnico permanece fiel aos dados assinados.
- Responsividade mobile e impressão mantidas.

## P4 — privacidade
- HTML redige parâmetros de consulta, cabeçalhos de autorização/cookies e segredos em evidências, sem alterar os dados técnicos armazenados.
- Escape de HTML impede execução de markup proveniente dos scanners.
- Cobertura: `tests/test_report_export.mjs` e `tests/test_friendly_report.mjs`.

## P5 — validação obrigatória antes do merge
1. `python3 -m unittest discover -s tests -v`
2. Executar os testes Node do job `tests` em `.github/workflows/ci.yml`, incluindo callback, Worker, WebAuthn, relatórios, dashboard e dispatch.
   Para os testes Chromium, instalar Playwright/Chromium open source conforme o job `report_browser_e2e` (dependência exclusiva de QA, não do funcionamento do FluxOpen).
3. GitHub Actions: jobs `tests`, `scanner_smoke` e browser E2E, todos verdes.
4. Inspecionar `/health`, login, passkeys e sessão em implantação autorizada, **sem exibir ou rotacionar secrets**.
5. Verificar painel celular, download JSON/HTML, fluxo de callback e histórico do banco após publicação.
6. Se algum invariante falhar, suspender a publicação; rollback com `git revert` do merge e restaurar versão anterior do Worker, preservando D1 e secrets.

**Limites:** CI simula callbacks reais e verifica os contratos, mas não prova disponibilidade de credenciais de produção nem garante que um site-alvo autorize um scanner em tempo real. Escaneamento externo requer autorização explícita. Nenhuma auditoria ativa é executada como parte deste CI.
