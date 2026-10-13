import copy
import unittest

from verify_recipe import verify_lifecycle, verify_recipe, verify_tag_absent

TAG = 'epss-ecr-auth-' + 'a' * 40
POLICY = {'rules': [{'selection': {'tagStatus': 'tagged', 'tagPrefixList': ['sha-']},
                     'action': {'type': 'expire'}}]}


class PublicationTests(unittest.TestCase):
    def test_recipe_pins(self):
        verify_recipe()

    def test_sha_only_lifecycle_preserves_runtime(self):
        self.assertTrue(verify_lifecycle(POLICY, TAG))
        policy = copy.deepcopy(POLICY)
        policy['rules'].append({'selection': {'tagStatus': 'untagged'}, 'action': {'type': 'expire'}})
        self.assertTrue(verify_lifecycle(policy, TAG))

    def test_reject_broad_or_matching_lifecycle(self):
        for selection in ({'tagStatus': 'any'}, {'tagStatus': 'tagged'},
                          {'tagStatus': 'tagged', 'tagPrefixList': ['epss-']},
                          {'tagStatus': 'tagged', 'tagPatternList': ['*auth*']}):
            with self.subTest(selection=selection), self.assertRaises(ValueError):
                verify_lifecycle({'rules': [{'selection': selection}]}, TAG)
        with self.assertRaises(ValueError):
            verify_lifecycle({}, TAG)
        with self.assertRaises(ValueError):
            verify_lifecycle(POLICY, 'sha-' + 'a' * 40)

    def test_only_exact_image_not_found_proves_absence(self):
        verify_tag_absent({'images': [], 'failures': [{'failureCode': 'ImageNotFound', 'imageId': {'imageTag': TAG}}]}, TAG)
        for response in ({'images': [{}]}, {}, {'failures': [{'failureCode': 'AccessDenied', 'imageId': {'imageTag': TAG}}]},
                         {'failures': [{'failureCode': 'ImageNotFound', 'imageId': {'imageTag': 'other'}}]}):
            with self.subTest(response=response), self.assertRaises(ValueError):
                verify_tag_absent(response, TAG)


if __name__ == '__main__':
    unittest.main()
