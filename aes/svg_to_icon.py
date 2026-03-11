import os
from PIL import Image
import cairosvg

def create_standard_ico():
    svg_file = "icon.svg"
    temp_png = "temp_256.png"
    ico_file = "icon.ico"
    
    if not os.path.exists(svg_file):
        print(f"错误：找不到 {svg_file}")
        return

    print("正在生成图标...")
    
    # 1. SVG 转高清 PNG
    cairosvg.svg2png(url=svg_file, write_to=temp_png, output_width=256, output_height=256)
    
    # 2. 生成包含多尺寸的 ICO (Windows 必备尺寸)
    img = Image.open(temp_png)
    img.save(
        ico_file,
        format="ICO",
        sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)]
    )
    
    # 3. 清理临时文件
    img.close()
    os.remove(temp_png)
    
    print(f"✅ 成功生成 {ico_file}")

if __name__ == "__main__":
    create_standard_ico()