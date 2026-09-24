import unittest
from preflight import inspect

BASE = 'apiVersion: ax.io/v1alpha1\nkind: Task\nmetadata:\n  name: demo\nspec:\n  image: registry.internal/agent@sha256:' + 'a' * 64 + '\n'


class PreflightTests(unittest.TestCase):
    def test_bounded_task(self):
        self.assertTrue(inspect(BASE, internal_hosts=['registry.internal'])['passed_static_checks'])

    def test_external_image(self):
        self.assertFalse(inspect(BASE)['passed_static_checks'])

    def test_connected_allows_external(self):
        self.assertTrue(inspect(BASE, profile='connected')['passed_static_checks'])

    def test_secret_value_not_emitted(self):
        report = inspect(BASE + '  env:\n    - name: API_KEY\n      value: DO_NOT_PRINT\n')
        self.assertNotIn('DO_NOT_PRINT', str(report))
        self.assertIn('INLINE_CREDENTIAL', str(report))

    def test_missing_workspace(self):
        self.assertIn('UNRESOLVED_REFERENCE', str(inspect(BASE + '  workspaces:\n    - name: absent\n')))

    def test_duplicate_yaml_key(self):
        with self.assertRaises(ValueError):
            inspect(BASE + '  image: duplicate\n')

    def test_alias_rejected(self):
        with self.assertRaises(ValueError):
            inspect('a: &a [*a]')

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            inspect('')

    def test_disconnected_model_not_certified(self):
        report = inspect('apiVersion: ax.io/v1alpha1\nkind: Model\nmetadata: {name: m}\nspec: {provider: google}', profile='disconnected')
        self.assertIn('MODEL_OFFLINE_UNVERIFIED', str(report))


if __name__ == '__main__':
    unittest.main()
