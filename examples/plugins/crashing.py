"""A deliberately broken plugin used by the test-suite: the tool must survive it."""
from android_forensics.plugin_api import ArtifactParser, register


@register
class Crashing(ArtifactParser):
    name = "crashing"

    def identify(self, tables, ctx):
        raise RuntimeError("boom in identify")

    def extract(self, session, match, ctx):
        yield from ()

    def from_row(self, row, match, ctx):
        return None
