"""测试ZIP分析功能"""
import sys
import os
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(__file__))

from solvers.common import extract_strings, find_flags_in_text, find_flags_in_strings

def test_zip_analysis(zip_path):
    print(f"测试文件: {zip_path}")
    print("=" * 50)

    import zipfile

    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            print(f"ZIP文件包含 {len(zf.infolist())} 个文件")

            extract_dir = zip_path + "_test_extracted"
            zf.extractall(extract_dir)

            for root, dirs, files in os.walk(extract_dir):
                for f in files:
                    fpath = os.path.join(root, f)
                    print(f"\n分析文件: {f}")
                    print("-" * 30)

                    with open(fpath, 'rb') as fp:
                        data = fp.read()
                        print(f"文件大小: {len(data)} 字节")
                        print(f"前20字节: {data[:20]}")

                        # 检查是否是PE文件
                        if data[:2] == b'MZ':
                            print("检测到PE文件")

                            try:
                                import pefile
                                pe = pefile.PE(data=data)

                                # 提取内存映射
                                raw_data = pe.get_memory_mapped_image()
                                print(f"内存映射大小: {len(raw_data)} 字节")

                                # 提取字符串
                                all_strings = extract_strings(raw_data)
                                print(f"提取到 {len(all_strings)} 个字符串")

                                # 搜索flag
                                flags = find_flags_in_strings(all_strings)
                                print(f"找到的flag: {flags}")

                                # 搜索DBAPP
                                for s in all_strings:
                                    if 'DBAPP' in s:
                                        print(f"找到DBAPP字符串: {s}")

                                # 搜索所有包含{的字符串
                                for s in all_strings:
                                    if '{' in s and '}' in s:
                                        print(f"找到可能的flag: {s}")

                                pe.close()
                            except Exception as e:
                                print(f"pefile分析失败: {e}")
                                print("使用基础分析...")
                                all_strings = extract_strings(data)
                                print(f"提取到 {len(all_strings)} 个字符串")
                                flags = find_flags_in_strings(all_strings)
                                print(f"找到的flag: {flags}")
                        else:
                            print("非PE文件，使用基础分析")
                            all_strings = extract_strings(data)
                            print(f"提取到 {len(all_strings)} 个字符串")
                            flags = find_flags_in_strings(all_strings)
                            print(f"找到的flag: {flags}")

            # 清理
            import shutil
            shutil.rmtree(extract_dir, ignore_errors=True)

    except Exception as e:
        print(f"错误: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    if len(sys.argv) > 1:
        test_zip_analysis(sys.argv[1])
    else:
        print("用法: python test_zip.py <zip文件路径>")
