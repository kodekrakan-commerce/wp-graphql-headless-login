<?php
declare(strict_types=1);

use PHPUnit\Framework\TestCase;
use Tests\WPGraphQL\Constraint\QueryConstraint;
use Tests\WPGraphQL\Constraint\QueryErrorConstraint;
use Tests\WPGraphQL\Constraint\QuerySuccessfulConstraint;
use Tests\WPGraphQL\Logger\PHPUnitLogger;

final class ClosureRecordingLogger extends PHPUnitLogger {
    public array $events = [];
    public function logData($data) { $this->events[] = $data; }
}
final class ClosureInspectableConstraint extends QueryConstraint {
    public function substring(string $haystack, string $needle, int $mode): bool {
        return $this->findSubstring($haystack, $needle, $mode);
    }
}
final class QueryConstraintsTest extends TestCase {
    private function field(string $type, string $path, $value): array {
        return ['type' => $type, 'path' => $path, 'expected_value' => $value, 'is_group' => false];
    }
    public function testEnvelopeAcceptanceAndFailureMessages(): void {
        foreach ([[], [['data' => []]], ['unrelated' => true]] as $invalid) {
            $constraint = new QueryConstraint(new PHPUnitLogger());
            self::assertFalse($constraint->matches($invalid));
            self::assertStringContainsString('invalid', strtolower($constraint->failureDescription($invalid)));
        }
        self::assertTrue((new QueryConstraint(new PHPUnitLogger()))->matches(['data' => []]));
        self::assertTrue((new QuerySuccessfulConstraint(new PHPUnitLogger()))->matches(['data' => ['name' => 'fixture']]));
        self::assertFalse((new QuerySuccessfulConstraint(new PHPUnitLogger()))->matches(['errors' => [['message' => 'denied']]]));
        self::assertFalse((new QueryErrorConstraint(new PHPUnitLogger()))->matches(['data' => []]));
    }
    public function testFieldObjectNodeEdgeSuffixAndNegationRules(): void {
        $response = ['data' => ['name' => 'fixture', 'viewer' => ['id' => 'u1'], 'nodes' => [['id' => 'u1']], 'edges' => [['node' => ['id' => 'u1']]]]];
        $rules = [
            $this->field('FIELD', 'name', 'fixture'),
            $this->field('!FIELD', 'name', 'different'),
            $this->field('OBJECT', 'viewer', [$this->field('FIELD', 'id', 'u1')]),
            $this->field('NODE', 'nodes', [$this->field('FIELD', 'id', 'u1')]),
            $this->field('EDGE', 'edges', [$this->field('FIELD', 'id', 'u1')]),
        ];
        self::assertTrue((new QuerySuccessfulConstraint(new PHPUnitLogger(), $rules))->matches($response));
        $wrong = new QuerySuccessfulConstraint(new PHPUnitLogger(), [$this->field('FIELD', 'name', 'wrong')]);
        self::assertFalse($wrong->matches($response));
        self::assertStringContainsString('name', $wrong->failureDescription($response));
        self::assertFalse((new QuerySuccessfulConstraint(new PHPUnitLogger(), [$this->field('!FIELD', 'name', 'fixture')]))->matches($response));
    }
    public function testErrorMessagePathInvalidRuleAndLoggerContract(): void {
        $response = ['errors' => [['message' => 'ação denied', 'path' => ['viewer', 'name']]]];
        $logger = new ClosureRecordingLogger();
        $valid = new QueryErrorConstraint($logger, [
            ['type' => 'ERROR_PATH', 'path' => 'viewer.name'],
            ['type' => 'ERROR_MESSAGE', 'needle' => 'ação', 'search_type' => PHPUnitLogger::MESSAGE_STARTS_WITH],
            ['type' => 'ERROR_MESSAGE', 'needle' => 'denied', 'search_type' => PHPUnitLogger::MESSAGE_ENDS_WITH],
        ]);
        self::assertTrue($valid->matches($response));
        self::assertNotEmpty($logger->events);
        foreach ([['type' => 'ERROR_PATH', 'path' => 'wrong.path'], ['type' => 'ERROR_UNKNOWN'], []] as $rule) {
            $constraint = new QueryErrorConstraint($logger, [$rule]);
            self::assertFalse($constraint->matches($response));
            self::assertNotSame('', $constraint->failureDescription($response));
        }
        $old = $_SERVER['argv'];
        try {
            $_SERVER['argv'] = array_values(array_diff($old, ['--debug', '--verbose']));
            ob_start();
            (new PHPUnitLogger())->logData(['fixture' => 'quiet']);
            self::assertSame('', ob_get_clean());
        } finally { $_SERVER['argv'] = $old; }
    }
    /** @dataProvider substringVectors */
    public function testRealInheritedNativeSubstringBehavior(string $haystack, string $needle, int $mode, bool $expected): void {
        self::assertSame($expected, (new ClosureInspectableConstraint(new PHPUnitLogger()))->substring($haystack, $needle, $mode));
    }
    public static function substringVectors(): array {
        $rows = [];
        foreach ([PHPUnitLogger::MESSAGE_STARTS_WITH, PHPUnitLogger::MESSAGE_ENDS_WITH] as $mode) {
            $rows[] = ['ação', 'ação', $mode, true];
            $rows[] = ['ação', '', $mode, true];
            $rows[] = ['', '', $mode, true];
            $rows[] = ['', 'a', $mode, false];
            $rows[] = ['Fixture', 'fixture', $mode, false];
            $rows[] = ['ação', 'other', $mode, false];
        }
        $rows[] = ['ação final', 'ação', PHPUnitLogger::MESSAGE_STARTS_WITH, true];
        $rows[] = ['ação final', 'final', PHPUnitLogger::MESSAGE_ENDS_WITH, true];
        return $rows;
    }
}
