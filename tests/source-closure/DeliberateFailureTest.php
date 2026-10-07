<?php
declare(strict_types=1);
final class DeliberateFailureTest extends PHPUnit\Framework\TestCase {
    public function testFailureMustPropagate(): void {
        self::assertSame('expected controlled value', 'deliberately different value');
    }
}
