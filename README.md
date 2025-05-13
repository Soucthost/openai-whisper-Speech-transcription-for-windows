# openai-whisper-Speech-transcription-for-windows
Speech transcription English and Simplified Chinese  Based on openai/whisper
# 简体中文实时语音转写软件使用说明

## 部署到本地，windoows系统。
下载模型把models文件夹放到_internal文件夹内  模型下载链接:https://huggingface.co/john2223/medium-model/tree/main
## 软件功能

这款软件能够实时录制和转写语音，自动将任何中文（包括繁体中文）转换为简体中文。无论说话者使用的是什么中文方言或繁体中文表达，都会被自动转换并保存为标准简体中文文本。


1. 运行 `语音实时转写.exe`
2. 首次使用时需要进行授权验证
   - 点击"申请授权"获取设备序列号
   - 将序列号发送给开发者获取授权文件
   - 将授权文件 `license.json` 放在程序同一目录下
3. 授权通过后，点击"开始录音+转写"按钮开始工作
4. 录音完成后点击"停止"按钮结束录音
5. 转写的文本自动保存在程序目录下的 `transcripts` 文件夹中，以日期和小时命名

## 转写文件说明

转写文件按照日期和小时自动生成和保存，格式为 `YYYY-MM-DD_HH.txt`。同一小时内的转写内容会自动追加到对应的文件中，每一条转写内容前会标记具体的时间 `[HH:MM:SS]`。

## 特别说明

1. 本程序使用 CPU 进行推理，性能取决于您的计算机配置
2. 所有识别的文本都会自动转换为简体中文
3. 转写质量受限于环境噪音和语音清晰度
4. 完整的转写历史记录可在程序目录下的 `log.txt` 文件中查看

## 技术支持

如遇任何问题，请联系软件开发者获取支持。
联系方式，微信: johnwong6666
