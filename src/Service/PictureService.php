<?php

namespace App\Service;

use Exception;
use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\HttpFoundation\File\UploadedFile;

class PictureService
{
    public function createImageFromJpeg($imagePath)
    {
        if (!file_exists($imagePath)) {
            throw new \Exception("File not found: $imagePath");
        }

        // Call the GD function with the global namespace
        $image = \imagecreatefromjpeg($imagePath);

        if ($image === false) {
            throw new \Exception("Failed to create image from JPEG");
        }

        // Perform operations on the image
        return $image;
    }

    private $params;

    public function __construct(ParameterBagInterface $params)
    {
        $this->params = $params;
    }

    public function add(UploadedFile $picture, ?string $folder = '', ?int $width = 250, ?int $height = 250)
    {
        // Generate a new name for the image
        $fichier = md5(uniqid(rand(), true)) . '.webp';

        // Get the file's real path
        $picturePath = $picture->getRealPath();

        // Get image information
        $picture_infos = \getimagesize($picturePath);

        if ($picture_infos === false) {
            throw new Exception('Invalid image format');
        }

        // Check the image format
        switch ($picture_infos['mime']) {
            case 'image/png':
                $picture_source = \imagecreatefrompng($picturePath);
                break;
            case 'image/jpeg':
                // Correct way to call GD functions with the global namespace
                $picture_source = \imagecreatefromjpeg($picturePath);

                break;
            case 'image/webp':
                $picture_source = \imagecreatefromwebp($picturePath);
                break;
            default:
                throw new Exception('Invalid image format');
        }

        // Crop the image
        $imageWidth = $picture_infos[0];
        $imageHeight = $picture_infos[1];

        switch ($imageWidth <=> $imageHeight) {
            case -1: // Portrait
                $squareSize = $imageWidth;
                $src_x = 0;
                $src_y = ($imageHeight - $squareSize) / 2;
                break;
            case 0: // Square
                $squareSize = $imageWidth;
                $src_x = 0;
                $src_y = 0;
                break;
            case 1: // Landscape
                $squareSize = $imageHeight;
                $src_x = ($imageWidth - $squareSize) / 2;
                $src_y = 0;
                break;
        }

        // Create a new blank image
        $resized_picture = \imagecreatetruecolor($width, $height);

        \imagecopyresampled($resized_picture, $picture_source, 0, 0, $src_x, $src_y, $width, $height, $squareSize, $squareSize);

        $path = $this->params->get('images_directory') . DIRECTORY_SEPARATOR . $folder;

        // Create the destination folder if it doesn't exist
        if (!\file_exists($path . DIRECTORY_SEPARATOR . 'mini' . DIRECTORY_SEPARATOR)) {
            \mkdir($path . DIRECTORY_SEPARATOR . 'mini' . DIRECTORY_SEPARATOR, 0755, true);
        }

        // Store the cropped image
        \imagewebp($resized_picture, $path . DIRECTORY_SEPARATOR . 'mini' . DIRECTORY_SEPARATOR . $width . 'x' . $height . '-' . $fichier);

        $picture->move($path . DIRECTORY_SEPARATOR, $fichier);

        return $fichier;
    }

    public function delete(string $fichier, ?string $folder = '', ?int $width = 250, ?int $height = 250)
    {
        if ($fichier !== 'default.webp') {
            $success = false;
            $path = $this->params->get('images_directory') . DIRECTORY_SEPARATOR . $folder;

            $mini = $path . DIRECTORY_SEPARATOR . 'mini' . DIRECTORY_SEPARATOR . $width . 'x' . $height . '-' . $fichier;

            if (\file_exists($mini)) {
                \unlink($mini);
                $success = true;
            }

            $original = $path . DIRECTORY_SEPARATOR . $fichier;

            if (\file_exists($original)) {
                \unlink($original);
                $success = true;
            }
            return $success;
        }
        return false;
    }
}
