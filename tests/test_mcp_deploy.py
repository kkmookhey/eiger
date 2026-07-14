from halcyon.bank import Bank
from halcyon.crm_fixtures import SEED
from halcyon.mcp_deploy import CORE_ASGI, CRM_ASGI, core_banking_app, crm_app
from halcyon.mcp_vault import SERVER_CORE, SERVER_CRM, TokenVault


def test_deploy_apps_build():
    v = TokenVault({SERVER_CORE: "a", SERVER_CRM: "b"})
    assert core_banking_app(Bank(), v) is not None
    assert crm_app(Bank(), v, SEED) is not None


def test_module_level_asgi_apps_import_cleanly():
    assert CORE_ASGI is not None
    assert CRM_ASGI is not None
