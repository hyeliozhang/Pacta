#!/usr/bin/env python3
import copy, pathlib, sys, unittest
ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "prototype"))
from pacta_core.page_index import PageCubeIndex, SimplePolicy, digest, project, summary_key

class PageIndexTest(unittest.TestCase):
    def test_page_cube_certificate_and_tamper(self):
        idx = PageCubeIndex(20000, page_size=1024, fanout=16)
        pol = SimplePolicy(tenant=1, regions=(0,1,2), max_sensitivity=2)
        cert = idx.certificate(100, 150, pol)
        self.assertTrue(idx.verify(cert, 100, 150, pol))
        cert['result'] = dict(cert['result'])
        if cert['result']:
            k = next(iter(cert['result']))
            cert['result'][k][0] += 1
        self.assertFalse(idx.verify(cert, 100, 150, pol))

    def test_page_cube_binds_certificate_query_and_descriptor(self):
        idx = PageCubeIndex(20000, page_size=1024, fanout=16)
        pol = SimplePolicy(tenant=1, regions=(0,1,2), max_sensitivity=2)
        cert = idx.certificate(100, 150, pol)
        self.assertTrue(idx.verify(cert, 100, 150, pol))
        cert['query'] = dict(cert['query'])
        cert['query']['lo'] = 99
        self.assertFalse(idx.verify(cert, 100, 150, pol))
        cert = idx.certificate(100, 150, pol)
        cert['descriptor'] = dict(cert['descriptor'])
        cert['descriptor']['page_size'] = 2048
        self.assertFalse(idx.verify(cert, 100, 150, pol))

    def test_page_cube_rejects_boundary_cover_substitution(self):
        idx = PageCubeIndex(20000, page_size=1024, fanout=16)
        pol = SimplePolicy(tenant=1, regions=(0,1,2), max_sensitivity=2)
        cert = idx.certificate(100, 150, pol)
        self.assertTrue(idx.verify(cert, 100, 150, pol))

        bad = copy.deepcopy(cert)

        # Preserve the opened page descriptor fields while replacing exact
        # boundary evidence with a full-page cover.  A verifier that only checks
        # hashes, but not cover containment, would accept after the claimed
        # result is adjusted to the broader page summary.
        def mutate(node):
            if node.get('kind') == 'open_page':
                full = {}
                for r in node['rows']:
                    k = summary_key(r)
                    c, total = full.get(k, [0, 0])
                    full[k] = [c + 1, total + int(r['amount'])]
                old = project(node['range_summary'], pol)
                new = project(full, pol)
                descriptor = {k: node[k] for k in ('min', 'max', 'count', 'hash', 'page_digest')}
                node.clear()
                node.update({
                    'kind': 'cover',
                    **descriptor,
                    'summary': full,
                    'summary_digest': digest('summary', full),
                })
                return old, new
            for child in node.get('children', []):
                out = mutate(child)
                if out is not None:
                    return out
            return None

        old_new = mutate(bad['proof'])
        self.assertIsNotNone(old_new, 'range should expose at least one boundary page')
        old, new = old_new
        claimed = {int(k): tuple(v) for k, v in bad['result'].items()}
        for cat, (c, total) in old.items():
            oc, ot = claimed.get(cat, (0, 0))
            claimed[cat] = (oc - c, ot - total)
        for cat, (c, total) in new.items():
            oc, ot = claimed.get(cat, (0, 0))
            claimed[cat] = (oc + c, ot + total)
        bad['result'] = {str(k): [v[0], v[1]] for k, v in sorted(claimed.items()) if v != (0, 0)}
        self.assertFalse(idx.verify(bad, 100, 150, pol))

    def test_page_cube_rejects_ambiguous_query_encoding(self):
        idx = PageCubeIndex(1000, page_size=64, fanout=8)
        pol = SimplePolicy(tenant=1, regions=(0,1,2), max_sensitivity=2)
        cert = idx.certificate(1, 2, pol)
        self.assertTrue(idx.verify(cert, 1, 2, pol))
        bad = copy.deepcopy(cert)
        bad['query'] = dict(bad['query'])
        bad['query']['lo'] = True
        self.assertFalse(idx.verify(bad, 1, 2, pol))

if __name__ == '__main__':
    unittest.main()
