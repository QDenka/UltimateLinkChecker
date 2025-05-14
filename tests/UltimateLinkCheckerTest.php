<?php

declare(strict_types=1);

namespace Qdenka\UltimateLinkChecker\Tests;

use PHPUnit\Framework\TestCase;
use Qdenka\UltimateLinkChecker\Contract\ProviderInterface;
use Qdenka\UltimateLinkChecker\Exception\InvalidArgumentException;
use Qdenka\UltimateLinkChecker\Exception\ProviderNotFoundException;
use Qdenka\UltimateLinkChecker\Result\AggregateResult;
use Qdenka\UltimateLinkChecker\Result\CheckResult;
use Qdenka\UltimateLinkChecker\UltimateLinkChecker;

final class UltimateLinkCheckerTest extends TestCase
{
    private UltimateLinkChecker $checker;
    private ProviderInterface $mockProvider;

    protected function setUp(): void
    {
        $this->mockProvider = $this->createMock(ProviderInterface::class);
        $this->mockProvider->method('getName')->willReturn('mock_provider');

        $this->checker = new UltimateLinkChecker();
        $this->checker->addProvider($this->mockProvider);
    }

    public function testAddProviderAddsProvider(): void
    {
        $providers = $this->checker->getProviders();

        $this->assertCount(1, $providers);
        $this->assertArrayHasKey('mock_provider', $providers);
        $this->assertSame($this->mockProvider, $providers['mock_provider']);
    }

    public function testRemoveProviderRemovesProvider(): void
    {
        $this->checker->removeProvider('mock_provider');

        $this->assertEmpty($this->checker->getProviders());
    }

    public function testGetProviderReturnsProvider(): void
    {
        $provider = $this->checker->getProvider('mock_provider');

        $this->assertSame($this->mockProvider, $provider);
    }

    public function testGetProviderThrowsExceptionWhenProviderNotFound(): void
    {
        $this->expectException(ProviderNotFoundException::class);

        $this->checker->getProvider('non_existent_provider');
    }

    public function testCheckCallsProviderCheck(): void
    {
        $mockResult = new CheckResult('https://example.com');

        $this->mockProvider->expects($this->once())
            ->method('check')
            ->with('https://example.com')
            ->willReturn($mockResult);

        $result = $this->checker->check('https://example.com');

        $this->assertInstanceOf(AggregateResult::class, $result);
        $this->assertTrue($result->isSafe());
    }

    public function testCheckWithSpecificProviders(): void
    {
        $mockResult = new CheckResult('https://example.com');

        $this->mockProvider->expects($this->once())
            ->method('check')
            ->with('https://example.com')
            ->willReturn($mockResult);

        $result = $this->checker->check('https://example.com', ['mock_provider']);

        $this->assertInstanceOf(AggregateResult::class, $result);
    }

    public function testCheckWithNonExistentProviderThrowsException(): void
    {
        $this->expectException(ProviderNotFoundException::class);

        $this->checker->check('https://example.com', ['non_existent_provider']);
    }

    public function testCheckWithInvalidConsensusThrowsException(): void
    {
        $this->expectException(InvalidArgumentException::class);

        $this->checker->check('https://example.com', null, 'invalid_consensus');
    }

    public function testCheckBatchChecksMultipleUrls(): void
    {
        $mockResult = new CheckResult('https://example.com');

        $this->mockProvider->expects($this->exactly(2))
            ->method('check')
            ->willReturn($mockResult);

        $results = $this->checker->checkBatch([
            'https://example.com',
            'https://another-example.com'
        ]);

        $this->assertCount(2, $results);
        $this->assertArrayHasKey('https://example.com', $results);
        $this->assertArrayHasKey('https://another-example.com', $results);
        $this->assertInstanceOf(AggregateResult::class, $results['https://example.com']);
        $this->assertInstanceOf(AggregateResult::class, $results['https://another-example.com']);
    }

    public function testCheckAsyncReturnsPromise(): void
    {
        $mockResult = new CheckResult('https://example.com');

        $this->mockProvider->expects($this->once())
            ->method('check')
            ->willReturn($mockResult);

        $promise = $this->checker->checkAsync('https://example.com');

        $this->assertInstanceOf(\React\Promise\PromiseInterface::class, $promise);
    }

    public function testCheckBatchAsyncReturnsPromises(): void
    {
        $mockResult = new CheckResult('https://example.com');

        $this->mockProvider->expects($this->exactly(2))
            ->method('check')
            ->willReturn($mockResult);

        $promises = $this->checker->checkBatchAsync([
            'https://example.com',
            'https://another-example.com'
        ]);

        $this->assertCount(2, $promises);
        $this->assertArrayHasKey('https://example.com', $promises);
        $this->assertArrayHasKey('https://another-example.com', $promises);
        $this->assertInstanceOf(\React\Promise\PromiseInterface::class, $promises['https://example.com']);
        $this->assertInstanceOf(\React\Promise\PromiseInterface::class, $promises['https://another-example.com']);
    }
}
