param([string]$PreviewPath)
$ErrorActionPreference='Stop'
Add-Type -AssemblyName System.Drawing
$frames=@()
foreach($size in @(16,24,32,48,64,128,256)) {
 $bmp=[Drawing.Bitmap]::new($size,$size)
 $g=[Drawing.Graphics]::FromImage($bmp)
 $g.SmoothingMode=[Drawing.Drawing2D.SmoothingMode]::AntiAlias
 $g.ScaleTransform($size/256.0,$size/256.0)
 $navy=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#102C46'))
 $teal=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#35D6C5'))
 $white=[Drawing.SolidBrush]::new([Drawing.ColorTranslator]::FromHtml('#FFFFFF'))
 $pen=[Drawing.Pen]::new($white,12)
 $shape=[Drawing.Drawing2D.GraphicsPath]::new()
 $shape.AddArc(8,8,64,64,180,90);$shape.AddArc(184,8,64,64,270,90)
 $shape.AddArc(184,184,64,64,0,90);$shape.AddArc(8,184,64,64,90,90);$shape.CloseFigure()
 $g.FillPath($navy,$shape)
 $g.DrawRectangle($pen,45,52,166,116)
 $g.FillRectangle($white,116,174,24,21)
 $g.FillRectangle($white,88,195,80,10)
 $g.FillPolygon($teal,[Drawing.Point[]]@([Drawing.Point]::new(71,83),[Drawing.Point]::new(153,83),[Drawing.Point]::new(153,68),[Drawing.Point]::new(184,97),[Drawing.Point]::new(153,126),[Drawing.Point]::new(153,111),[Drawing.Point]::new(71,111)))
 $g.FillPolygon($white,[Drawing.Point[]]@([Drawing.Point]::new(185,130),[Drawing.Point]::new(103,130),[Drawing.Point]::new(103,118),[Drawing.Point]::new(76,142),[Drawing.Point]::new(103,157),[Drawing.Point]::new(103,150),[Drawing.Point]::new(185,150)))
 $stream=[IO.MemoryStream]::new()
 $bmp.Save($stream,[Drawing.Imaging.ImageFormat]::Png)
 $frames+=,@{size=$size;bytes=$stream.ToArray()}
 if($size -eq 256 -and $PreviewPath){$bmp.Save($PreviewPath,[Drawing.Imaging.ImageFormat]::Png)}
 $stream.Dispose();$g.Dispose();$bmp.Dispose();$shape.Dispose();$pen.Dispose();$navy.Dispose();$teal.Dispose();$white.Dispose()
}
$output=Join-Path $PSScriptRoot '..\flutter\windows\runner\resources\remote_desktop.ico'
$writer=[IO.BinaryWriter]::new([IO.File]::Create($output))
try {
 $writer.Write([uint16]0);$writer.Write([uint16]1);$writer.Write([uint16]$frames.Count)
 $offset=6+16*$frames.Count
 foreach($frame in $frames){
  $dimension=if($frame.size -eq 256){0}else{$frame.size}
  $writer.Write([byte]$dimension);$writer.Write([byte]$dimension);$writer.Write([byte]0);$writer.Write([byte]0)
  $writer.Write([uint16]1);$writer.Write([uint16]32);$writer.Write([uint32]$frame.bytes.Length);$writer.Write([uint32]$offset)
  $offset+=$frame.bytes.Length
 }
 foreach($frame in $frames){$writer.Write([byte[]]$frame.bytes)}
}finally{$writer.Dispose()}
