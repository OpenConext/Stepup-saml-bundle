<?php

declare(strict_types=1);

use Rector\Config\RectorConfig;

return RectorConfig::configure()
    ->withPaths([
         __DIR__ . '/../../src',
    ])
    ->withPhpSets()
    ->withAttributesSets(all: true)
    ->withComposerBased(phpunit: true, symfony: true)
    ->withTypeCoverageLevel(10)
    ->withDeadCodeLevel(10)
    ->withCodeQualityLevel(10)
    ->withSkip([
        \Rector\Php84\Rector\MethodCall\NewMethodCallWithoutParenthesesRector::class,
        \Rector\Php84\Rector\Class_\DeprecatedAnnotationToDeprecatedAttributeRector::class,
    ]);
