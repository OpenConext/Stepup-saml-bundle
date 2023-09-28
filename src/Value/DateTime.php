<?php declare(strict_types=1);

/**
 * Copyright 2023 SURFnet B.V.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Surfnet\SamlBundle\Value;

use DateInterval;
use DateTime as CoreDateTime;
use Stringable;
use Surfnet\SamlBundle\Exception\InvalidArgumentException;

/**
 * @SuppressWarnings(PHPMD.TooManyPublicMethods) due to comparison methods
 */
class DateTime implements Stringable
{
    /**
     * This string can also be used with `DateTime::createFromString()`.
     */
    final public const FORMAT = DATE_ATOM;

    /**
     * Allows for mocking of time.
     */
    private static ?self $now = null;

    private readonly CoreDateTime $dateTime;

    public static function now(): self
    {
        return self::$now ?: new self(new CoreDateTime);
    }

    /**
     * @param string $string A date-time string formatted using `self::FORMAT` (eg. '2014-11-26T15:20:43+01:00').
     */
    public static function fromString(string $string): self
    {
        $dateTime = CoreDateTime::createFromFormat(self::FORMAT, $string);

        if ($dateTime === false) {
            throw new InvalidArgumentException('Date-time string could not be parsed: is it formatted correctly?');
        }

        return new self($dateTime);
    }

    public function __construct(?CoreDateTime $dateTime = null)
    {
        $this->dateTime = $dateTime ?: new CoreDateTime();
    }

    public function add(DateInterval $interval): self
    {
        $dateTime = clone $this->dateTime;
        $dateTime->add($interval);

        return new self($dateTime);
    }

    public function sub(DateInterval $interval): self
    {
        $dateTime = clone $this->dateTime;
        $dateTime->sub($interval);

        return new self($dateTime);
    }

    public function comesBefore(DateTime $dateTime): bool
    {
        return $this->dateTime < $dateTime->dateTime;
    }

    public function comesBeforeOrIsEqual(DateTime $dateTime): bool
    {
        return $this->dateTime <= $dateTime->dateTime;
    }

    public function comesAfter(DateTime $dateTime): bool
    {
        return $this->dateTime > $dateTime->dateTime;
    }

    public function comesAfterOrIsEqual(DateTime $dateTime): bool
    {
        return $this->dateTime >= $dateTime->dateTime;
    }

    public function format(string $format): string
    {
        return $this->dateTime->format($format);
    }

    /**
     * @return string An ISO 8601 representation of this DateTime.
     */
    public function __toString(): string
    {
        return $this->format(self::FORMAT);
    }
}
