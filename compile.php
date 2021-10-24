<?php

try {
    // Generate a version
    $version = 'v1.0.0';

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


    // $phar->startBuffering();

    // Create the default stub from main.php entrypoint
    $phar["Crypto.php"] = file_get_contents($srcRoot . "/tools/ca/Crypto.php");
    // // Set the default stub
    // $phar->setStub($phar->createDefaultStub("index.php"));
    // // Add the rest of the apps files
    // $phar->buildFromDirectory($srcRoot);

    // $phar->stopBuffering();


    // plus - compressing it into gzip  
    $phar->compressFiles(Phar::GZ);

    # Make the file executable
    chmod($pharFile, 0770);

    // `cp -r $srcRoot/resources $buildRoot`;

    echo "$pharFile successfully created" . PHP_EOL;
} catch (Exception $e) {
    echo $e->getMessage();
}
