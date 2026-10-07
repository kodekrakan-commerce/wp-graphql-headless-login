<?php
declare(strict_types=1);

/** Separate Windows lane: an absent Windows/MSYS2 admission is a failure, never a skipped pass. */
final class WindowsProcessSecurityTest extends PHPUnit\Framework\TestCase {
    public function testGenuineUpstreamMsysSentinelRegression(): void {
        self::assertSame('\\', DIRECTORY_SEPARATOR, 'This required gate must run on admitted Windows, not a skipped POSIX test.');
        self::assertNotFalse(getenv('MSYSTEM'), 'An admitted MSYS2/Git Bash environment is required.');
        $cwd = getcwd();
        $temp = sys_get_temp_dir() . '/headless-msys-' . bin2hex(random_bytes(8));
        mkdir($temp, 0700);
        chdir($temp);
        file_put_contents('=foo.txt', 'This is a test file.');
        try {
            $process = new Symfony\Component\Process\Process(['type', substr_replace(getcwd(), '=foo.txt', 2)]);
            $process->mustRun();
            self::assertSame('This is a test file.', $process->getOutput());
            self::assertSame(sprintf('type "%s=foo.txt"', substr(getcwd(), 0, 2)), $process->getCommandLine());
        } finally {
            unlink('=foo.txt');
            chdir($cwd);
            rmdir($temp);
        }
    }
}
