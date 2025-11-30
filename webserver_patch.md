# Webserver Patch

## Current Vulnerable Code Issues

- **No file extension validation** - Accepts any file extension including `.php`, `.phtml`, `.php5`
- **No MIME type verification** - Only checks upload error, not actual file content
- **No content inspection** - Doesn't scan for executable code
- **Predictable filename** - Uses original filename, making shell execution easy
- **Public accessibility** - Files in uploads are directly accessible via HTTP

## Patch Strategy

### 1. Whitelist Allowed Extensions

```php
<?php
$allowed_extensions = ['pdf', 'jpg', 'jpeg', 'png', 'txt'];
$file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
if (!in_array($file_ext, $allowed_extensions)) {
    $error = "Invalid file type. Only PDF, JPG, PNG, and TXT files are allowed.";
}
?>
```

### 2. Verify MIME Type (prevents extension spoofing)

```php
<?php
$allowed_mimetypes = [
    'application/pdf',
    'image/jpeg',
    'image/png',
    'text/plain'
];

$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime_type = finfo_file($finfo, $tmp_name);
finfo_close($finfo);

if (!in_array($mime_type, $allowed_mimetypes)) {
    $error = "File content does not match allowed types.";
}
?>
```

### 3. Complete Secure Upload Implementation



```php

//Replace line 13-32 of upload.php with the following code.

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['receipt'])) {
    $file = $_FILES['receipt'];
    
    // Define allowed extensions and MIME types
    $allowed_extensions = ['pdf', 'jpg', 'jpeg', 'png'];
    $allowed_mimetypes = [
        'application/pdf',
        'image/jpeg',
        'image/png',
        'text/plain'
    ];
    
    if ($file['error'] === UPLOAD_ERR_OK) {
        $filename = $file['name'];
        $tmp_name = $file['tmp_name'];
        
        // Validate extension
        $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
        if (!in_array($file_ext, $allowed_extensions)) {
            $error = "Invalid file type. Only PDF, JPG, and PNG files are allowed.";
        } else {
            // Validate MIME type
            $finfo = finfo_open(FILEINFO_MIME_TYPE);
            $mime_type = finfo_file($finfo, $tmp_name);
            finfo_close($finfo);
            
            if (!in_array($mime_type, $allowed_mimetypes)) {
                $error = "File content does not match allowed types.";
            } else {
                $target_path = $upload_dir . $filename;
                
                if (move_uploaded_file($tmp_name, $target_path)) {
                    $message = "Receipt uploaded successfully! File saved as: " . htmlspecialchars($filename);
                } else {
                    $error = "Failed to upload file.";
                }
            }
        }
    } else {
        $error = "Upload error: " . $file['error'];
    }
}

```