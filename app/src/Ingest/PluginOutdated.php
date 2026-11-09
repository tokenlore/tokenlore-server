<?php

declare(strict_types=1);

namespace Tokenlore\Ingest;

// Lieferung eines Plugins älter als die Mindestversion (Limits::MIN_PLUGIN_VERSION): der Handler antwortet mit 426
// {"error":"plugin_outdated","min_plugin_version":…} (Abschnitt „Mindestversion“ in protocol/doc.md).
final class PluginOutdated extends \RuntimeException
{
}
