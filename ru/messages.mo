��          �      <      �     �  
   �     �     �      �          +     G  "   a     �     �     �  .   �     �  �    M   �  �     t  �  1   s     �  ,   �  1   �  J   	  #   b	  C   �	     �	  6   �	      
      .
  8   O
  \   �
  *   �
  �    �   �  �   �                                                      
                                           	     is dependency for  not found Can't copy %s to %s Can't create directory %s Can't make hard link for file %s Can't run %s Dependency tree is too deep Destination directory is  Destination firmware directory is  Module  Source directory is  Source firmware directory is  There are more than one module with same name  Unrecognized option %s Usage: copyko [OPTION] <module> ... <dest>
Copy kernel modules (ko-files) and its' dependencies to <dest> directory
The program is useful when creating Live CD

Options:
  -f, --from=FROM  directory to search kernel modules
      --fwsrc=FROM directory to search firmware
      --fwdst=TO   directory to store firmware
  -l, --link       try to make hard links instead of copy files
  -v, --verbose    explain what is being done
      --help       display this help and exit
      --version    output version information and exit
Report bugs to: oks-mgn@mail.ru
copyko home page: https://github.com/Konstantin-2/copyko.git
General help using GNU software: <https://www.gnu.org/gethelp/>
 You can omit dependency modules because they are autocopied by other modules. copyko 0.1
Copyright (C) 2019 Oshepkov Kosntantin
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
 Project-Id-Version: copyko 0.1
Report-Msgid-Bugs-To: 
PO-Revision-Date: 2019-05-01 00:26+0500
Last-Translator: <oks-mgn@mail.ru>
Language-Team: Russian
Language: ru
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit
Plural-Forms: nplurals=3; plural=(n%10==1 && n%100!=11 ? 0 : n%10>=2 && n%10<=4 && (n%100<10 || n%100>=20) ? 1 : 2);
  является зависимостью для  не найден Ошибка копирования %s в %s Ошибка создания каталога %s Ошибка создания жесткой ссылки на файл %s Не могу запустить %s Дерево зависимостей слишком большое Целевой каталог  Целевой каталог для прошивок  Модуль  Каталог-источник  Каталог-источник с прошивками  Найдено несколько модулей с одинаковым названием  Нераспознанная опция %s Использование: copyko [ОПЦИИ] <ko-файл> ... <целевой каталог>
Копирует заданные модули ядра (<ko-файлы>) и их зависимости в <целевой каталог>
Программа полезна при создании загрузочных CD-дисков

Опции:
  -f, --from=откуда  каталог, в котором искать модули ядра
      --fwsrc=откуда каталог, в котором искать прошивки
      --fwdst=куда   каталог, в который копировать прошивки
  -l, --link         пытаться делать жесткие ссылки вместо копирования
  -v, --verbose      показывать дополнительную информацию
      --help         показать эту справку и завершить работу
      --version      показать версию программы и завершить работу
Об ошибках сообщайте по адресу: oks-mgn@mail.ru
copyko в Интернете: https://github.com/Konstantin-2/copyko.git
General help using GNU software: <https://www.gnu.org/gethelp/>
 Вы можете не указывать явно эти файлы, они скорируются автоматически как зависимости. copyko 0.1
Copyright (C) 2019 Oshepkov Kosntantin 
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
 