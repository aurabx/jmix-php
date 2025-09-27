<?php

declare(strict_types=1);

namespace AuraBox\Jmix\Tests;

use AuraBox\Jmix\JmixBuilder;
use AuraBox\Jmix\Exceptions\JmixException;
use PHPUnit\Framework\TestCase;

class JmixBuilderTest extends TestCase
{
    private JmixBuilder $builder;
    private string $tempDir;

    protected function setUp(): void
    {
        $this->builder = new JmixBuilder();
        $this->tempDir = sys_get_temp_dir() . '/jmix_test_' . uniqid('', true);
        mkdir($this->tempDir, 0755, true);
    }

    protected function tearDown(): void
    {
        $this->cleanupDirectory($this->tempDir);
    }

    public function testBuildFromDicomWithValidConfig(): void
    {
        // Create a dummy DICOM file
        $dicomPath = $this->tempDir . '/dicom';
        mkdir($dicomPath, 0755, true);
        $dummyDicomFile = $dicomPath . '/test.dcm';
        $dummyData = str_repeat("\x00", 128) . 'DICM' . str_repeat("\x00", 100);
        file_put_contents($dummyDicomFile, $dummyData);

        $config = $this->getValidConfig();
        
        $envelope = $this->builder->buildFromDicom($dicomPath, $config);

        $this->assertIsArray($envelope);
        $this->assertArrayHasKey('manifest', $envelope);
        $this->assertArrayHasKey('metadata', $envelope);
        $this->assertArrayHasKey('transmission', $envelope);

        // Check manifest structure
        $manifest = $envelope['manifest'];
        $this->assertEquals('1.0', $manifest['version']);
        $this->assertNotEmpty($manifest['id']);
        $this->assertNotEmpty($manifest['timestamp']);
        $this->assertEquals('Radiology Clinic A', $manifest['sender']['name']);

        // Check metadata structure
        $metadata = $envelope['metadata'];
        $this->assertIsArray($metadata['patient']['name']);
        $this->assertEquals('Jane Doe', $metadata['patient']['name']['text']);
        $this->assertEquals('Doe', $metadata['patient']['name']['family']);
        $this->assertEquals(['Jane'], $metadata['patient']['name']['given']);
        $this->assertEquals('1975-02-14', $metadata['patient']['dob']);
        $this->assertIsArray($metadata['studies']['series']);
    }

    public function testBuildFromDicomWithNonExistentPath(): void
    {
        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('DICOM path does not exist');

        $config = $this->getValidConfig();
        $this->builder->buildFromDicom('/non/existent/path', $config);
    }

    public function testBuildFromDicomWithEmptyFolder(): void
    {
        $emptyPath = $this->tempDir . '/empty';
        mkdir($emptyPath, 0755, true);

        $this->expectException(JmixException::class);
        $this->expectExceptionMessage('No DICOM files found');

        $config = $this->getValidConfig();
        $this->builder->buildFromDicom($emptyPath, $config);
    }

    public function testSaveToFiles(): void
    {
        // Create a dummy DICOM file
        $dicomPath = $this->tempDir . '/dicom';
        mkdir($dicomPath, 0755, true);
        $dummyDicomFile = $dicomPath . '/test.dcm';
        $dummyData = str_repeat("\x00", 128) . 'DICM' . str_repeat("\x00", 100);
        file_put_contents($dummyDicomFile, $dummyData);

        $config = $this->getValidConfig();
        $envelope = $this->builder->buildFromDicom($dicomPath, $config);

        $outputPath = $this->tempDir . '/output';
        $this->builder->saveToFiles($envelope, $outputPath);

        $this->assertFileExists($outputPath . '/manifest.json');
        $this->assertFileExists($outputPath . '/metadata.json');
        $this->assertFileExists($outputPath . '/transmission.json');

        // Verify JSON structure
        $manifestJson = json_decode(file_get_contents($outputPath . '/manifest.json'), true);
        $this->assertIsArray($manifestJson);
        $this->assertEquals('Radiology Clinic A', $manifestJson['sender']['name']);
    }

    private function getValidConfig(): array
    {
        return [
            'sender' => [
                'name' => 'Radiology Clinic A',
                'id' => 'org:au.gov.health.123456',
                'contact' => 'imaging@clinica.org.au',
            ],
            'requester' => [
                'name' => 'Dr John Smith',
                'id' => 'org:au.gov.health.55555',
                'contact' => 'smith@clinicb.org.au',
            ],
            'receivers' => [
                [
                    'name' => 'Radiology Clinic B',
                    'id' => 'org:au.gov.health.987654',
                    'contact' => [
                        'system' => 'phone',
                        'value' => '+61049555555',
                    ],
                ],
            ],
            'patient' => [
                'name' => 'Jane Doe',
                'dob' => '1975-02-14',
                'sex' => 'F',
                'ihi' => '8003608166690503',
                'identifiers' => [
                    [
                        'system' => 'http://ns.electronichealth.net.au/id/ihi/1.0',
                        'value' => '8003608166690503',
                    ],
                ],
            ],
        ];
    }

    private function cleanupDirectory(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }

        $files = array_diff(scandir($dir), ['.', '..']);
        foreach ($files as $file) {
            $filePath = $dir . '/' . $file;
            if (is_dir($filePath)) {
                $this->cleanupDirectory($filePath);
            } else {
                unlink($filePath);
            }
        }
        rmdir($dir);
    }
}