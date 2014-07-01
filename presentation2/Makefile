TC = pdflatex -shell-escape
TEX = bdgka0.tex bdgka1.tex bdgka2.tex bdgka3.tex
PNG = ${TEX:.tex=.png}

all: ${PNG}

%.png: %.tex
	${TC} $<

clean:
	@echo cleaning
	@rm -f ${PNG} *.{aux,log,pdf}

.PHONY: all clean
