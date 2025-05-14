# Ultimate Link Checker

![License](https://img.shields.io/github/license/qdenka/ultimatelinkchecker)
![PHP Version](https://img.shields.io/badge/php-8.1%2B-blue.svg)
![Tests](https://img.shields.io/github/workflow/status/qdenka/ultimatelinkchecker/tests/main)
![Coverage](https://img.shields.io/codecov/c/github/qdenka/ultimatelinkchecker)

A powerful, flexible PHP library for checking links against multiple security services.

## Features

- 🔍 Check URLs against multiple security services with a unified API
- 🚀 Supports Google Safe Browsing, Yandex Safe Browsing, Facebook, VirusTotal, and more
- ⚡ Asynchronous checking capability with Promise-based API
- 🔧 Easily extensible to add new providers
- 💾 Optional caching of results to reduce API calls
- 📊 Detailed threat information and comprehensive reports

## Installation

```bash
composer require qdenka/ultimatelinkchecker
```

## Requirements

- PHP 8.1 or higher
- Composer
- API keys for the services you want to use

## Quick Start

```php
use Qdenka\UltimateLinkChecker\UltimateLinkChecker;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;

// Create the link checker with a provider
$checker = new UltimateLinkChecker();
$checker->addProvider(new GoogleSafeBrowsingProvider('your-api-key'));

// Check a single URL
$result = $checker->check('https://example.com');

// Check if it's safe
if ($result->isSafe()) {
    echo "The URL is safe!";
} else {
    echo "The URL is unsafe: " . $result->getThreatType();
}

// Check multiple URLs at once
$results = $checker->checkBatch([
    'https://example.com',
    'https://another-example.com'
]);

foreach ($results as $url => $result) {
    echo "$url: " . ($result->isSafe() ? "Safe" : "Unsafe") . PHP_EOL;
}
```

## Using Multiple Providers

```php
use Qdenka\UltimateLinkChecker\UltimateLinkChecker;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Provider\YandexSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Provider\VirusTotalProvider;

$checker = new UltimateLinkChecker();

// Add multiple providers
$checker->addProvider(new GoogleSafeBrowsingProvider('google-api-key'));
$checker->addProvider(new YandexSafeBrowsingProvider('yandex-api-key'));
$checker->addProvider(new VirusTotalProvider('virustotal-api-key'));

// Check against all providers (uses PHP 8.1 named arguments)
$result = $checker->check(
    url: 'https://example.com',
    consensus: UltimateLinkChecker::CONSENSUS_ANY // or CONSENSUS_ALL, CONSENSUS_MAJORITY
);

if ($result->isSafe()) {
    echo "The URL is considered safe by the selected consensus method";
} else {
    echo "The URL is unsafe";
    $threats = $result->getThreats();
    
    foreach ($threats as $providerName => $threat) {
        echo "$providerName: " . $threat->getDescription() . PHP_EOL;
    }
}
```

## Asynchronous Checking

```php
use Qdenka\UltimateLinkChecker\UltimateLinkChecker;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Provider\YandexSafeBrowsingProvider;

$checker = new UltimateLinkChecker();
$checker->addProvider(new GoogleSafeBrowsingProvider('google-api-key'));
$checker->addProvider(new YandexSafeBrowsingProvider('yandex-api-key'));

// Get promises for multiple URLs
$promises = $checker->checkBatchAsync([
    'https://example1.com',
    'https://example2.com',
    'https://example3.com',
]);

// Process results as they come in
foreach ($promises as $url => $promise) {
    $promise->then(
        function ($result) use ($url) {
            echo "$url is " . ($result->isSafe() ? "safe" : "unsafe") . PHP_EOL;
        },
        function ($error) use ($url) {
            echo "Error checking $url: " . $error->getMessage() . PHP_EOL;
        }
    );
}

// Wait for all promises to complete
\React\Promise\all($promises)->wait();
```

## Available Providers

- Google Safe Browsing
- Yandex Safe Browsing
- VirusTotal
- Facebook URL Security
- PhishTank
- OPSWAT MetaDefender
- Cisco Talos
- IPQualityScore

## Creating Your Own Provider

```php
use Qdenka\UltimateLinkChecker\Contract\ProviderInterface;
use Qdenka\UltimateLinkChecker\Result\CheckResult;
use Qdenka\UltimateLinkChecker\Result\Threat;

class MyCustomProvider implements ProviderInterface
{
    public function getName(): string
    {
        return 'my_custom_provider';
    }
    
    public function check(string $url): CheckResult
    {
        // Your implementation to check the URL
        $isSafe = true; // Your logic here
        
        $result = new CheckResult($url);
        
        if (!$isSafe) {
            $threat = new Threat(
                type: 'MALWARE',
                platform: 'ANY_PLATFORM',
                description: 'This URL contains malware'
            );
            $result->addThreat($this->getName(), $threat);
        }
        
        return $result;
    }
    
    public function checkBatch(array $urls): array
    {
        // Implement batch checking for better performance
        $results = [];
        foreach ($urls as $url) {
            $results[$url] = $this->check($url);
        }
        return $results;
    }
}
```

## Advanced Configuration

```php
use Qdenka\UltimateLinkChecker\UltimateLinkChecker;
use Qdenka\UltimateLinkChecker\Provider\GoogleSafeBrowsingProvider;
use Qdenka\UltimateLinkChecker\Cache\RedisCacheAdapter;
use Qdenka\UltimateLinkChecker\Config\CheckerConfig;

// Create a configuration
$config = new CheckerConfig();
$config->setCacheAdapter(new RedisCacheAdapter($redisClient));
$config->setCacheTtl(3600); // Cache results for 1 hour
$config->setTimeout(5.0); // 5 second timeout for API calls
$config->setRetries(2); // Retry API calls twice

// Create checker with config
$checker = new UltimateLinkChecker($config);
$checker->addProvider(new GoogleSafeBrowsingProvider('api-key'));

// Now all checks will use the configured cache and timeout settings
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Credits

Created with ❤️ by [qdenka](https://github.com/qdenka)
