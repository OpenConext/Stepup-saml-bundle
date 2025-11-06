<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;

return RectorConfig::configure()
    ->withPaths([
         __DIR__ . '/../../src',
    ])
    ->withAttributesSets(all: true)
    ->withComposerBased(phpunit: true, symfony: true)
    ->withTypeCoverageLevel(10)
    ->withDeadCodeLevel(10)
    ->withCodeQualityLevel(10);
