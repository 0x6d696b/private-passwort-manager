"""Safety boundaries for the Docker validation script's disposable resource handling."""
import copy
import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "validate_containers.py"
SPEC = importlib.util.spec_from_file_location("validate_containers", SCRIPT)
validation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(validation)


class IsolationTests(unittest.TestCase):
    def setUp(self):
        self.project = "vault-validation-example"
        self.model = {
            "name": self.project,
            "services": {
                "api": {"volumes": [{"type": "volume", "source": "vault_data", "target": "/data"}]},
                "proxy": {},
            },
            "volumes": {"vault_data": {"name": self.project + "_vault_data"}},
            "networks": {"backend": {"name": self.project + "_backend"}},
        }

    def test_disposable_project_is_accepted(self):
        validation.validate_isolation(self.model, self.project)

    def test_existing_or_external_volume_is_rejected(self):
        for change in ({"name": "production_vault_data"}, {"external": True}):
            with self.subTest(change=change):
                model = copy.deepcopy(self.model)
                model["volumes"]["vault_data"].update(change)
                with self.assertRaises(RuntimeError):
                    validation.validate_isolation(model, self.project)

    def test_host_mounts_and_explicit_container_names_are_rejected(self):
        model = copy.deepcopy(self.model)
        model["services"]["api"]["volumes"][0]["type"] = "bind"
        with self.assertRaises(RuntimeError):
            validation.validate_isolation(model, self.project)
        self.model["services"]["api"]["container_name"] = "existing-api"
        with self.assertRaises(RuntimeError):
            validation.validate_isolation(self.model, self.project)

    def test_wrong_project_and_network_are_rejected(self):
        with self.assertRaises(RuntimeError):
            validation.validate_isolation(self.model, "normal-project")
        self.model["networks"]["backend"]["name"] = "production_backend"
        with self.assertRaises(RuntimeError):
            validation.validate_isolation(self.model, self.project)


if __name__ == "__main__":
    unittest.main()
