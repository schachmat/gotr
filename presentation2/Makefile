TC = pdflatex -shell-escape
TEX = bdgka0.tex
PNG = ${TEX:.tex=.png}

all: ${PNG}

${PNG}: ${TEX}
	@echo pdflatex -shell-escape $<
	@${TC} $< 2>/dev/null

clean:
	@echo cleaning
	@rm -f ${PNG} *.{aux,log,pdf}

.PHONY: all clean
