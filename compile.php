<?php

try {
    // Generate a version
    $version = 'v0.0.1';

    // Get the current directory
    $curDir = getcwd();
    // The root source codes path
    $srcRoot = "$curDir/src";
    // The build phar file path
    $buildRoot = "$curDir/build";

    // The phar file
    $pharFile = $buildRoot . "/ca-api.$version.phar";

    // Clean up
    if (file_exists($pharFile)) 
    {
        unlink($pharFile);
    }

    if (file_exists($pharFile . '.gz')) 
    {
        unlink($pharFile . '.gz');
    }

    // Create phar
    $phar = new Phar($pharFile);

    // Start buffering. Mandatory to modify stub to add shebang
    $phar->startBuffering();

    // Create the default stub from main.php entrypoint
    $phar["Crypto.php"] = file_get_contents($srcRoot . "/tools/Crypto.php");
    // $phar->setStub($phar->createDefaultStub("index.php"));

    // // Create the default stub from main.php entrypoint
    // $defaultStub = $phar->createDefaultStub('/public/index.php');

    // // Add the rest of the apps files
    // $phar->buildFromDirectory($srcRoot);

    // // Customize the stub to add the shebang
    // $stub = "#!/usr/bin/env php \n" . $defaultStub;

    // // Add the stub
    // $phar->setStub($stub);

    $phar->stopBuffering();

    // plus - compressing it into gzip  
    $phar->compressFiles(Phar::GZ);

    # Make the file executable
    chmod($pharFile, 0770);

    // `cp -r $srcRoot/resources $buildRoot`;

    echo "$pharFile successfully created" . PHP_EOL;
} catch (Exception $e) {
    echo $e->getMessage();
}
