<?php
declare(strict_types=1);

use Composer\Util\ProcessExecutor;
use Facebook\WebDriver\Remote\Service\DriverService;
use lucatume\WPBrowser\Adapters\Symfony\Component\Process\Process as BrowserProcess;
use lucatume\WPBrowser\Process\Worker\WorkerProcess;
use lucatume\WPBrowser\WordPress\CliProcess;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Exception\ProcessTimedOutException;
use Symfony\Component\Process\Process;

final class ProcessConsumersTest extends TestCase {
    private string $cwd;
    protected function setUp(): void {
        $this->cwd = sys_get_temp_dir() . '/headless-process-' . bin2hex(random_bytes(8));
        mkdir($this->cwd, 0700);
    }
    protected function tearDown(): void {
        rmdir($this->cwd);
    }
    private function command(): array {
        return [PHP_BINARY, __DIR__ . '/child.php', 'roundtrip', 'with spaces', '"quotes"', '', 'ação', 'a=b'];
    }
    public function testRealProcessArgumentEnvironmentAndOutputContract(): void {
        $process = new Process($this->command(), $this->cwd, ['HEADLESS_CHILD_VALUE' => 'fixture']);
        self::assertSame(0, $process->run());
        $output = json_decode($process->getOutput(), true, 512, JSON_THROW_ON_ERROR);
        self::assertSame(array_slice($this->command(), 3), $output['args']);
        self::assertSame($this->cwd, $output['cwd']);
        self::assertSame('fixture', $output['env']);
        self::assertSame('controlled stderr', $process->getErrorOutput());
        self::assertFalse($process->isRunning());
        self::assertSame(realpath(dirname(__DIR__, 2) . '/vendor/symfony/process/Process.php'), realpath((new ReflectionClass($process))->getFileName()));
    }
    public function testNonzeroExitAndTimeoutRemainObservable(): void {
        $failure = new Process([PHP_BINARY, __DIR__ . '/child.php', 'exit']);
        self::assertSame(7, $failure->run());
        self::assertSame('controlled failure', $failure->getErrorOutput());
        $slow = new Process([PHP_BINARY, __DIR__ . '/child.php', 'wait'], null, null, null, 0.05);
        try {
            $slow->run();
            self::fail('Controlled timeout was not propagated.');
        } catch (ProcessTimedOutException $exception) {
            self::assertTrue($exception->isGeneralTimeout());
        } finally {
            $slow->stop(0);
            self::assertFalse($slow->isRunning());
        }
    }
    /** @dataProvider upstreamEscapingVectors */
    public function testGenuineUpstreamEscapingVectorRoundTrip($arg): void {
        $process = new Process([PHP_BINARY, '-r', 'echo $argv[1];', $arg]);
        self::assertSame(0, $process->run());
        self::assertSame((string) $arg, $process->getOutput());
    }
    public static function upstreamEscapingVectors(): iterable {
        yield ['a"b%c%'];
        yield ['a"b^c^'];
        yield ["a\nb'c"];
        yield ['a^b c!'];
        yield ["a!b\tc"];
        yield ['a\\\\"\\"'];
        yield ['éÉèÈàÀöä'];
        yield [null];
        yield [1];
        yield [1.1];
    }
    public function testShellFactoryAndComposerSynchronousAsynchronousConsumers(): void {
        $shell = implode(' ', array_map('escapeshellarg', $this->command()));
        self::assertSame(0, Process::fromShellCommandline($shell, $this->cwd)->run());
        $executor = new ProcessExecutor();
        $output = null;
        self::assertSame(0, $executor->execute($this->command(), $output, $this->cwd));
        self::assertSame(array_slice($this->command(), 3), json_decode($output, true)['args']);
        self::assertSame(0, $executor->execute($shell, $output, $this->cwd));
        $executor->enableAsync();
        $settled = null;
        $executor->executeAsync($this->command(), $this->cwd)->then(static function (Process $process) use (&$settled): void { $settled = $process; });
        $executor->wait();
        self::assertInstanceOf(Process::class, $settled);
        self::assertSame(0, $settled->getExitCode());
        self::assertSame(array_slice($this->command(), 3), json_decode($settled->getOutput(), true)['args']);
    }
    public function testBrowserAdapterWorkerStreamsAndStopPaths(): void {
        $adapter = new BrowserProcess($this->command(), $this->cwd);
        $adapter->start();
        self::assertIsFloat($adapter->getStartTime());
        self::assertSame(0, $adapter->wait());
        $shell = BrowserProcess::fromShellCommandline(implode(' ', array_map('escapeshellarg', $this->command())), $this->cwd);
        self::assertInstanceOf(BrowserProcess::class, $shell);
        self::assertSame(0, $shell->run());
        $worker = new WorkerProcess($this->command(), $this->cwd);
        $worker->start();
        self::assertIsResource($worker->getStdoutStream());
        self::assertIsResource($worker->getStdErrStream());
        self::assertSame(0, $worker->wait());
        $running = new BrowserProcess([PHP_BINARY, __DIR__ . '/child.php', 'wait']);
        $running->start();
        $running->stop(0);
        self::assertFalse($running->isRunning());
    }
    public function testAdapterExplicitConstructorOptionsAreNotSilentlyLost(): void {
        $adapter = new BrowserProcess($this->command(), $this->cwd, null, null, 60, ['suppress_errors' => false]);
        $options = new ReflectionProperty(Process::class, 'options');
        self::assertFalse($options->getValue($adapter)['suppress_errors'], 'A used sixth-argument option must preserve its semantics; failure blocks adapter acceptance.');
    }
    public function testWebDriverConstructsGenuineProcessWithoutStartingBrowser(): void {
        $service = new DriverService(PHP_BINARY, 45678, [__DIR__ . '/child.php', 'roundtrip']);
        $factory = new ReflectionMethod($service, 'createProcess');
        $process = $factory->invoke($service);
        self::assertInstanceOf(Process::class, $process);
        self::assertStringContainsString('child.php', $process->getCommandLine());
        self::assertFalse($process->isStarted());
    }
    public function testCliProcessUsesOnlyReviewedSourceLauncher(): void {
        $launcher = dirname(__DIR__, 2) . '/bin/security-wp-cli.php';
        self::assertTrue(is_executable($launcher));
        $process = new CliProcess(['cli', 'version'], $this->cwd, ['HEADLESS_CLOSURE_ADMISSION' => getenv('HEADLESS_CLOSURE_ADMISSION')], null, 10, $launcher);
        self::assertSame(0, $process->run());
        self::assertStringContainsString('2.12.0', $process->getOutput());
        self::assertStringContainsString($launcher, $process->getCommandLine());
        $dump = new CliProcess(['cli', 'cmd-dump'], $this->cwd, ['HEADLESS_CLOSURE_ADMISSION' => getenv('HEADLESS_CLOSURE_ADMISSION')], null, 10, $launcher);
        self::assertSame(0, $dump->run());
        $commands = json_decode($dump->getOutput(), true, 512, JSON_THROW_ON_ERROR);
        $names = array_column($commands['subcommands'], 'name');
        foreach (['cache', 'checksum', 'config', 'core', 'cron', 'db', 'embed', 'post', 'user', 'eval', 'export', 'plugin', 'theme', 'i18n', 'import', 'language', 'maintenance-mode', 'media', 'package', 'rewrite', 'role', 'scaffold', 'search-replace', 'server', 'shell', 'super-admin', 'widget'] as $name) {
            self::assertContains($name, $names, 'Default command missing: ' . $name);
        }
    }
}
